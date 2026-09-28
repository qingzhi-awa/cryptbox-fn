// Package main 飞牛（fnOS）服务端入口。
// 同时监听 TCP（客户端局域网同步，默认 5201）与 Unix Socket（统一网关，GATEWAY_SOCK 注入）。
package main

import (
	"bufio"
	"database/sql"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/gin-gonic/gin"

	"github.com/qingzhi-awa/cryptbox/shared/auth"
	"github.com/qingzhi-awa/cryptbox/shared/config"
	"github.com/qingzhi-awa/cryptbox/shared/crypto"
	"github.com/qingzhi-awa/cryptbox/shared/db"
	"github.com/qingzhi-awa/cryptbox/shared/handlers"
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

	// 迁移旧版本数据库文件名（passbook.db → app.db）。
	if err := migrateLegacyDB(cfg); err != nil {
		log.Fatalf("数据库迁移失败: %v", err)
	}

	database, err := db.Open(cfg)
	if err != nil {
		log.Fatalf("打开数据库失败: %v", err)
	}
	defer database.Close()

	// 首次安装时，从安装向导写入的初始化文件创建超级管理员与 SMTP 配置。
	if err := setupAdminFromInstall(database, cfg); err != nil {
		log.Fatalf("初始化管理员失败: %v", err)
	}
	if err := setupSMTPFromInstall(database, cfg); err != nil {
		log.Fatalf("初始化 SMTP 配置失败: %v", err)
	}
	if err := setupLanguageFromInstall(database, cfg); err != nil {
		log.Fatalf("初始化默认语言失败: %v", err)
	}

	encKey, err := crypto.GetOrCreateEncryptionKey(database)
	if err != nil {
		log.Fatalf("初始化加密密钥失败: %v", err)
	}

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	handlers.RegisterRoutes(r, cfg, database, encKey)

	handler := web.Serve(r)

	// TCP 监听：客户端局域网同步与飞牛端 Web 访问共用。认证统一走登录页 JWT，不使用网关头。
	tcpLn, err := net.Listen("tcp", ":"+cfg.Port)
	if err != nil {
		log.Fatalf("TCP 监听失败: %v", err)
	}
	log.Printf("密匣服务已启动: http://localhost:%s", cfg.Port)
	go func() {
		if err := http.Serve(tcpLn, handler); err != nil {
			log.Fatalf("TCP 服务退出: %v", err)
		}
	}()

	// Unix Socket 监听：飞牛统一网关（网关只转发到 target 目录下的 app.sock）
	if cfg.SockPath != "" {
		_ = os.Remove(cfg.SockPath)
		sockLn, err := net.Listen("unix", cfg.SockPath)
		if err != nil {
			log.Fatalf("Unix Socket 监听失败: %v", err)
		}
		_ = os.Chmod(cfg.SockPath, 0o666)
		log.Printf("统一网关 Socket 已监听: %s", cfg.SockPath)
		go func() {
			if err := http.Serve(sockLn, handler); err != nil {
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
	_, err = database.Exec(`UPDATE users SET password_hash = ? WHERE id = ?`, hash, id)
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
	if username == "" || password == "" {
		return nil
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	_, err = db.SetupAdmin(database, username, hash)
	return err
}

// setupSMTPFromInstall 读取安装向导写入的 SMTP 配置（5 行：host/port/username/password/ssl），
// 若 host 非空则写入 meta。文件不存在时静默跳过，以兼容跳过 SMTP 或非向导安装场景。
func setupSMTPFromInstall(database *sql.DB, cfg config.Config) error {
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

	if err := db.SetMeta(database, "smtp_host", host); err != nil {
		return err
	}
	// 安装向导收集的是自定义 SMTP 服务器信息，标记为 custom，
	// 避免前端按预设厂商（默认 qq）只展示邮箱/授权码，导致 host/port/username 被隐藏。
	if err := db.SetMeta(database, "smtp_vendor", "custom"); err != nil {
		return err
	}
	if err := db.SetMeta(database, "smtp_port", port); err != nil {
		return err
	}
	if err := db.SetMeta(database, "smtp_username", username); err != nil {
		return err
	}
	if password != "" {
		if err := db.SetMeta(database, "smtp_password", password); err != nil {
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
