// Package main 飞牛（fnOS）服务端入口。
// 同时监听 TCP（客户端局域网同步，默认 5201）与 Unix Socket（统一网关，GATEWAY_SOCK 注入）。
package main

import (
	"bufio"
	"database/sql"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/gin-gonic/gin"

	"github.com/qingzhi-awa/cryptbox/shared/auth"
	"github.com/qingzhi-awa/cryptbox/shared/config"
	"github.com/qingzhi-awa/cryptbox/shared/crypto"
	"github.com/qingzhi-awa/cryptbox/shared/db"
	"github.com/qingzhi-awa/cryptbox/shared/handlers"
	auditlog "github.com/qingzhi-awa/cryptbox/shared/log"
	"github.com/qingzhi-awa/cryptbox/shared/tlsutil"
	"github.com/qingzhi-awa/cryptbox/shared/web"
)

func main() {
	cfg := config.Load()

	// CLI 模式：重置超级管理员密码后退出（供管理员 SSH 登录后本地执行，无需 SMTP）。
	if len(os.Args) > 1 && os.Args[1] == "-reset-admin" {
		password := ""
		if len(os.Args) >= 3 {
			password = os.Args[2]
		} else {
			// 未传密码参数时，从标准输入读取（避免密码出现在命令行历史）
			line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			password = strings.TrimRight(line, "\r\n")
		}
		if password == "" {
			log.Fatalf("用法: %s -reset-admin [新密码]（不传则从标准输入读取）", os.Args[0])
		}
		if err := resetAdminPassword(cfg, password); err != nil {
			log.Fatalf("重置密码失败: %v", err)
		}
		log.Println("超级管理员密码已重置")
		return
	}

	// CLI 模式：发送测试邮件验证 SMTP 配置后退出（供安装向导校验 SMTP）。
	if len(os.Args) > 1 && os.Args[1] == "-test-smtp" {
		if len(os.Args) < 7 {
			log.Fatalf("用法: %s -test-smtp <host> <port> <username> <ssl> <to>（口令从标准输入读取）", os.Args[0])
		}
		// R8-05：口令不走命令行参数，与 -reset-admin 一致改为从标准输入读取。
		if err := runTestSMTP(os.Args[2:], os.Stdin); err != nil {
			log.Fatalf("测试邮件发送失败: %v", err)
		}
		log.Println("测试邮件已发送")
		return
	}

	// 迁移旧版本数据库文件名（passbook.db → app.db）。
	if err := migrateLegacyDB(cfg); err != nil {
		log.Fatalf("数据库迁移失败: %v", err)
	}

	database, err := db.Open(cfg)
	if err != nil {
		log.Fatalf("打开数据库失败: %v", err)
	}
	defer database.Close()

	// 密钥治理（PT-07）：静态加密密钥与 JWT 签名密钥存放在数据目录下的独立
	// 文件（0600），不再与业务数据同放数据库；首次启动自动从 meta 迁移。
	// 加密密钥提前创建，供 SMTP 口令在写入口即时加密（R7-02）。
	encKey, err := crypto.GetOrCreateEncryptionKey(database, config.DataDir())
	if err != nil {
		log.Fatalf("初始化加密密钥失败: %v", err)
	}

	// 首次安装时，从安装向导写入的初始化文件创建超级管理员与 SMTP 配置。
	if err := setupAdminFromInstall(database, cfg); err != nil {
		log.Fatalf("初始化管理员失败: %v", err)
	}
	// SMTP 口令在写入口即时加密落库（R7-02），不再依赖后续迁移兜底。
	if err := setupSMTPFromInstall(database, cfg, encKey); err != nil {
		log.Fatalf("初始化 SMTP 配置失败: %v", err)
	}
	if err := setupLanguageFromInstall(database, cfg); err != nil {
		log.Fatalf("初始化默认语言失败: %v", err)
	}

	// 历史明文 SMTP 口令升级为密文存储（幂等，兼容旧库）。
	if err := auth.MigrateSMTPPassword(database, encKey); err != nil {
		log.Printf("警告：SMTP 口令加密迁移失败（可稍后重试）: %v", err)
	}

	// JWT 签名密钥：首次启动随机生成并持久化，避免硬编码默认值导致 token 可被伪造。
	jwtSecret, err := crypto.GetOrCreateJWTSecret(database, config.DataDir())
	if err != nil {
		log.Fatalf("初始化 JWT 密钥失败: %v", err)
	}
	if jwtSecret == "" {
		log.Fatalf("JWT 签名密钥为空，拒绝以不安全配置启动")
	}
	cfg.JWTSecret = jwtSecret

	// 进程级 XFF 开关仅作未标注入口的兜底；下方 TCP / Socket 监听均按入口
	// 显式标注信任决策（XFFTrustMiddleware），优先级高于此开关。
	auditlog.TrustProxyHeaders = cfg.TrustProxy

	// TLS 决策链（默认 HTTPS）：
	//   1. TLS_CERT / TLS_KEY 环境变量（正式证书）；
	//   2. 数据目录（TRIM_PKGVAR）已有证书（tls.crt/tls.key 或 cert.pem/key.pem）；
	//   3. 自动生成每实例独立的自签证书——飞牛场景装完即 HTTPS，浏览器首次访问信任一次即可。
	// 显式设置 DISABLE_TLS=true 时跳过以上全部，以明文 HTTP 运行（Web 后台将无法加密）。
	if cfg.DisableTLS {
		if cfg.ForceHTTPS {
			log.Fatalf("FORCE_HTTPS 与 DISABLE_TLS 冲突，请只设置其一。")
		}
		log.Printf("已设置 DISABLE_TLS=true，服务以明文 HTTP 运行；浏览器访问 Web 后台将无法使用端到端加密。")
	} else {
		if cfg.AutoDetectTLS() {
			log.Printf("已在数据目录发现证书，自动启用 HTTPS")
		} else if !cfg.TLSEnabled() {
			crt, key, created, err := tlsutil.EnsureSelfSigned(config.DataDir())
			if err != nil {
				log.Fatalf("自动生成自签证书失败: %v", err)
			}
			cfg.TLSCert, cfg.TLSKey = crt, key
			if created {
				log.Printf("已自动生成自签证书（本实例独立私钥）: %s", crt)
				log.Printf("浏览器首次访问时需信任一次证书；如需消除警告，可将该证书导入系统受信任的根证书颁发机构。")
			}
		}
		if cfg.ForceHTTPS {
			log.Printf("FORCE_HTTPS 已启用：仅提供 HTTPS 服务。")
		}
	}

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	handlers.RegisterRoutes(r, cfg, database, encKey)

	handler := web.Serve(r)

	// XFF 信任按入口区分：统一网关 Unix Socket 的 X-Forwarded-For 由网关注入、
	// 可信；直连 TCP 端口的 XFF 可能是客户端伪造，一律不采信。
	// 两者均覆盖 TRUST_PROXY 进程级开关，防止直连请求伪造来源 IP 绕过 IP 限流。
	sockHandler := auditlog.XFFTrustMiddleware(handler, true)
	tcpHandler := auditlog.XFFTrustMiddleware(handler, false)

	// TCP 监听：客户端局域网同步与飞牛端 Web 访问共用。认证统一走登录页 JWT，不使用网关头。
	tcpLn, err := net.Listen("tcp", ":"+cfg.Port)
	if err != nil {
		log.Fatalf("TCP 监听失败: %v", err)
	}
	if cfg.TLSEnabled() && !cfg.DisableTLS {
		// 同端口双协议：浏览器走 HTTPS（加密 + HSTS），
		// fnOS 的端口健康检查（checkport）与统一网关转发的明文 HTTP 保持兼容；
		// FORCE_HTTPS 时外部明文请求 301 到 HTTPS（本机转发豁免）。
		plain := http.Handler(tcpHandler)
		if cfg.ForceHTTPS {
			plain = tlsutil.ForceHTTPSRedirect(tcpHandler, cfg.Port)
		}
		log.Printf("密匣服务已启动: https://localhost:%s（同端口兼容 HTTP 明文探测/转发）", cfg.Port)
		if cfg.HTTPRedirectPort != "" {
			startHTTPRedirect(cfg.HTTPRedirectPort, cfg.Port)
		}
		go func() {
			if err := tlsutil.ServeDual(tcpLn, cfg.TLSCert, cfg.TLSKey, plain, tcpHandler); err != nil {
				log.Fatalf("TCP 服务退出: %v", err)
			}
		}()
	} else {
		log.Printf("密匣服务已启动: http://localhost:%s", cfg.Port)
		log.Printf("安全提示：未配置 TLS_CERT / TLS_KEY，局域网同步走明文 HTTP，登录口令与令牌可被嗅探；" +
			"建议配置证书后重启。")
		go func() {
			if err := http.Serve(tcpLn, tcpHandler); err != nil {
				log.Fatalf("TCP 服务退出: %v", err)
			}
		}()
	}

	// Unix Socket 监听：飞牛统一网关（网关只转发到 target 目录下的 app.sock）
	if cfg.SockPath != "" {
		_ = os.Remove(cfg.SockPath)
		sockLn, err := net.Listen("unix", cfg.SockPath)
		if err != nil {
			log.Fatalf("Unix Socket 监听失败: %v", err)
		}
		// 网关 socket 仅授予属主/属组访问（0600/0660），避免同机任意用户直连。
		_ = os.Chmod(cfg.SockPath, 0o660)
		// F6：0660 使属组内任意进程都能连接，而 socket 入口信任 X-Forwarded-For ——
		// 属组内进程可借此伪造来源 IP，绕过 IP 维度限流/锁定并污染审计来源。
		// 配置 GATEWAY_UID 后，仅在 Linux 上按 SO_PEERCRED 校验对端 UID，把信任边界
		// 从「整个属组」收紧到「网关进程本身」；未配置时维持现状并提示残余风险。
		var sockServeLn net.Listener = sockLn
		if uid, ok := gatewayUID(); ok {
			sockServeLn = uidGateListener{Listener: sockLn, allowUID: uid}
			log.Printf("统一网关 Socket 已启用对端凭据校验：仅接受 UID=%d 的连接", uid)
		} else {
			log.Printf("提示：网关 Socket 为 0660 且信任 X-Forwarded-For，属组内其他进程可伪造来源 IP；" +
				"若网关以固定用户运行，可设置 GATEWAY_UID=<uid> 收紧为仅该用户可连接。")
		}
		log.Printf("统一网关 Socket 已监听: %s", cfg.SockPath)
		go func() {
			if err := http.Serve(sockServeLn, sockHandler); err != nil {
				log.Fatalf("Socket 服务退出: %v", err)
			}
		}()
	}

	// 等待退出信号
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("收到退出信号，正在关闭...")
}

// runTestSMTP 执行 -test-smtp 子命令：host/port/username/ssl/to 依次取自 args
// （即 os.Args[2:]），SMTP 口令从 stdin 读取一行。
//
// 口令刻意不经命令行参数：argv 对同机所有本地用户可见（ps / /proc/<pid>/cmdline），
// 而 SMTP 授权码常与邮箱主口令相同，泄露会外溢到邮箱本体（R8-05）。
func runTestSMTP(args []string, stdin io.Reader) error {
	if len(args) < 5 {
		return fmt.Errorf("参数不足：需要 <host> <port> <username> <ssl> <to>")
	}
	host := args[0]
	port, err := strconv.Atoi(args[1])
	if err != nil {
		return fmt.Errorf("非法端口 %q: %w", args[1], err)
	}
	username := args[2]
	ssl := args[3] == "true"
	to := args[4]
	line, _ := bufio.NewReader(stdin).ReadString('\n')
	password := strings.TrimRight(line, "\r\n")
	return auth.TestSMTP(host, port, username, password, ssl, to)
}

// startHTTPRedirect 在明文端口上把所有 HTTP 请求 301 到 HTTPS。
func startHTTPRedirect(port, tlsPort string) {
	go func() {
		h := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			host := redirectHost(req.Host, tlsPort)
			http.Redirect(w, req, "https://"+host+req.RequestURI, http.StatusMovedPermanently)
		})
		log.Printf("HTTP -> HTTPS 重定向已监听: http://:%s", port)
		if err := http.ListenAndServe(":"+port, h); err != nil {
			log.Printf("HTTP 重定向端口退出: %v", err)
		}
	}()
}

// redirectHost 把请求 Host 的明文端口替换为 TLS 端口。
func redirectHost(host, tlsPort string) string {
	if host == "" {
		host = "localhost"
	}
	// 去掉明文端口（兼容 IPv6 字面量 [::1]:8080）。
	if strings.Contains(host, ":") && !strings.HasSuffix(host, "]") {
		if i := strings.LastIndex(host, ":"); i >= 0 {
			host = host[:i]
		}
	}
	if tlsPort != "443" {
		host = host + ":" + tlsPort
	}
	return host
}

// migrateLegacyDB 将旧版本数据库文件名 passbook.db 迁移为 app.db（仅当新库不存在且旧库存在时）。
func migrateLegacyDB(cfg config.Config) error {
	dir := filepath.Dir(cfg.DBDSN)
	oldPath := filepath.Join(dir, "passbook.db")

	if _, err := os.Stat(cfg.DBDSN); err == nil {
		return nil // 新库已存在，无需迁移
	}
	if _, err := os.Stat(oldPath); err != nil {
		return nil // 旧库不存在，无需迁移
	}
	return os.Rename(oldPath, cfg.DBDSN)
}

// resetAdminPassword 重置超级管理员密码（供管理员 SSH 登录后本地执行，无需 SMTP）。
func resetAdminPassword(cfg config.Config, newPassword string) error {
	if err := migrateLegacyDB(cfg); err != nil {
		return err
	}
	database, err := db.Open(cfg)
	if err != nil {
		return err
	}
	defer database.Close()

	var id int64
	err = database.QueryRow(`SELECT id FROM users WHERE role = 'superadmin' ORDER BY id LIMIT 1`).Scan(&id)
	if err != nil {
		err = database.QueryRow(`SELECT id FROM users WHERE role = 'admin' ORDER BY id LIMIT 1`).Scan(&id)
		if err != nil {
			return fmt.Errorf("未找到可重置的管理员账号")
		}
	}

	hash, err := auth.HashPassword(newPassword)
	if err != nil {
		return err
	}
	// 同时递增令牌版本：重置前泄露的令牌立即失效（PT-06）。
	_, err = database.Exec(`UPDATE users SET password_hash = ?, token_version = COALESCE(token_version, 0) + 1 WHERE id = ?`, hash, id)
	return err
}

// setupAdminFromInstall 读取安装向导写入的初始化文件（首行用户名、次行密码），
// 若系统尚未初始化则创建超级管理员并删除该文件。文件不存在时静默跳过，
// 以兼容非向导安装、升级或本地运行等场景。
// 初始化文件与数据库同目录（由 install_callback 写入 ${TRIM_PKGVAR}/setup.conf），
// 因此用 DBDSN 所在目录定位，避免依赖 TRIM_PKGVAR 是否被导出。
func setupAdminFromInstall(database *sql.DB, cfg config.Config) error {
	path := filepath.Join(filepath.Dir(cfg.DBDSN), "setup.conf")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil // 无初始化文件，跳过
	}
	_ = os.Remove(path) // 无论是否使用，消费掉该文件，避免重复初始化

	if db.IsInitialized(database) {
		return nil
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) < 2 {
		return nil
	}
	username := strings.TrimSpace(lines[0])
	password := lines[1] // 密码保留原样，不去空格
	email := ""
	if len(lines) >= 3 {
		// F5：邮箱大小写归一，与其余写入口口径一致。
		email = auth.NormalizeEmail(lines[2])
	}
	if username == "" || password == "" {
		return nil
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	_, err = db.SetupAdmin(database, username, hash, email, "")
	return err
}

// setupSMTPFromInstall 读取安装向导写入的 SMTP 配置（5 行：host/port/username/password/ssl），
// 若 host 非空则写入 meta。文件不存在时静默跳过，以兼容跳过 SMTP 或非向导安装场景。
// 口令在写入口即用服务端静态密钥加密（R7-02），避免明文落库窗口。
func setupSMTPFromInstall(database *sql.DB, cfg config.Config, encKey []byte) error {
	path := filepath.Join(filepath.Dir(cfg.DBDSN), "smtp.conf")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	_ = os.Remove(path)

	lines := strings.Split(string(data), "\n")
	if len(lines) < 5 {
		return nil
	}
	host := strings.TrimSpace(lines[0])
	if host == "" {
		return nil
	}
	port := strings.TrimSpace(lines[1])
	username := strings.TrimSpace(lines[2])
	password := lines[3] // 密码保留原样
	ssl := strings.TrimSpace(lines[4])
	vendor := "custom"
	if len(lines) >= 6 {
		if v := strings.TrimSpace(lines[5]); v != "" {
			vendor = v
		}
	}

	if err := db.SetMeta(database, "smtp_host", host); err != nil {
		return err
	}
	// vendor：优先使用安装向导选择的服务商；旧版本未写入时回退 custom。
	if err := db.SetMeta(database, "smtp_vendor", vendor); err != nil {
		return err
	}
	if err := db.SetMeta(database, "smtp_port", port); err != nil {
		return err
	}
	if err := db.SetMeta(database, "smtp_username", username); err != nil {
		return err
	}
	// 发件人地址：安装向导只收集「邮箱账号」，发件地址与账号一致。
	if err := db.SetMeta(database, "smtp_from", username); err != nil {
		return err
	}
	if password != "" {
		// 写入口即时加密（R7-02）：不再先落明文、依赖后续 MigrateSMTPPassword 兜底，
		// 消除"明文已落库、尚未加密"的窗口。EncryptSMTPPassword 幂等，随后再跑迁移也不会双重加密。
		enc, err := auth.EncryptSMTPPassword(encKey, password)
		if err != nil {
			return err
		}
		if err := db.SetMeta(database, "smtp_password", enc); err != nil {
			return err
		}
	}
	if ssl == "true" {
		_ = db.SetMeta(database, "smtp_ssl", "true")
	} else {
		_ = db.SetMeta(database, "smtp_ssl", "false")
	}
	return nil
}

// setupLanguageFromInstall 读取安装向导选择的默认语言（language.conf，仅英文版向导写入），
// 写入 meta 的 default_language；文件不存在时静默跳过（中文版默认 zh-CN）。
func setupLanguageFromInstall(database *sql.DB, cfg config.Config) error {
	path := filepath.Join(filepath.Dir(cfg.DBDSN), "language.conf")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	_ = os.Remove(path)

	lang := strings.TrimSpace(string(data))
	if lang == "" {
		return nil
	}
	return db.SetMeta(database, "default_language", lang)
}
