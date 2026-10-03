// Package handlers 提供 Gin HTTP 处理器、路由注册与中间件。
package handlers

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/qingzhi-awa/cryptbox/shared/auth"
	"github.com/qingzhi-awa/cryptbox/shared/config"
	"github.com/qingzhi-awa/cryptbox/shared/crypto"
	"github.com/qingzhi-awa/cryptbox/shared/csv"
	"github.com/qingzhi-awa/cryptbox/shared/db"
	"github.com/qingzhi-awa/cryptbox/shared/log"
	"github.com/qingzhi-awa/cryptbox/shared/ratelimit"
	"github.com/qingzhi-awa/cryptbox/shared/tlsutil"
	"github.com/qingzhi-awa/cryptbox/shared/uuid"
	"github.com/qingzhi-awa/cryptbox/shared/version"
	"github.com/qingzhi-awa/cryptbox/shared/web"
)

// maxJSONBody 是单个 API 请求体的上限。既覆盖整库上传的合理体积，
// 又避免超大请求造成内存与磁盘膨胀。
const maxJSONBody = 16 << 20 // 16MB

// 限流参数（进程内固定窗口，见 shared/ratelimit）。
const (
	loginIPPerMinute       = 30
	loginFailMax           = 5
	loginFailLockFor       = 15 * time.Minute
	registerIPPerMinute    = 10
	resetIPPerMinute       = 20
	resetEmailPerWindow    = 15
	resetEmailWindow       = 15 * time.Minute
	sendCodeIPPerHour      = 20
	sendCodeEmailPerWindow = 3
	sendCodeWindow         = 15 * time.Minute
)

// 会话凭据：Authorization（直连）/ X-Auth-Token（网关会保留自定义头）/ Cookie（网关不干预）。
// Cookie 有效期与 JWT 一致（见 shared/auth.GenerateToken）。
const (
	authCookieName   = "cryptbox_token"
	authCookieMaxAge = 24 * time.Hour
)

// Server 持有共享运行时状态（配置、数据库、加密密钥、限流器）。
type Server struct {
	Cfg    config.Config
	DB     *sql.DB
	EncKey []byte

	loginIP       *ratelimit.Limiter
	loginLock     *ratelimit.FailLocker
	registerIP    *ratelimit.Limiter
	resetIP       *ratelimit.Limiter
	resetEmail    *ratelimit.Limiter
	sendCodeIP    *ratelimit.Limiter
	sendCodeEmail *ratelimit.Limiter
}

// NewServer 构造一个 Server 实例。
func NewServer(cfg config.Config, database *sql.DB, encKey []byte) *Server {
	s := &Server{
		Cfg:    cfg,
		DB:     database,
		EncKey: encKey,

		loginIP:       ratelimit.New(loginIPPerMinute, time.Minute),
		loginLock:     ratelimit.NewFailLocker(loginFailMax, loginFailLockFor),
		registerIP:    ratelimit.New(registerIPPerMinute, time.Minute),
		resetIP:       ratelimit.New(resetIPPerMinute, time.Minute),
		resetEmail:    ratelimit.New(resetEmailPerWindow, resetEmailWindow),
		sendCodeIP:    ratelimit.New(sendCodeIPPerHour, time.Hour),
		sendCodeEmail: ratelimit.New(sendCodeEmailPerWindow, sendCodeWindow),
	}
	// 周期性清理过期计数，避免进程内 map 无限增长。
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			s.loginIP.Cleanup()
			s.loginLock.Cleanup()
			s.registerIP.Cleanup()
			s.resetIP.Cleanup()
			s.resetEmail.Cleanup()
			s.sendCodeIP.Cleanup()
			s.sendCodeEmail.Cleanup()
		}
	}()
	return s
}

// RegisterRoutes 在 gin.Engine 上注册全部 API 路由与 CORS 中间件。
func RegisterRoutes(r *gin.Engine, cfg config.Config, database *sql.DB, encKey []byte) {
	s := NewServer(cfg, database, encKey)
	s.register(r)
}

func (s *Server) register(r *gin.Engine) {
	r.Use(securityHeadersMiddleware(s.Cfg))
	r.Use(s.corsMiddleware())
	r.Use(bodyLimitMiddleware())
	// API 访问日志：把每个请求（方法/路径/状态/耗时）写入 info.log，便于网关场景排查。
	r.Use(accessLogMiddleware())

	api := r.Group("/api")
	{
		// 公开
		api.GET("/health", s.handleHealth)
		// 证书下载：自签证书本身是公开信息（每次 TLS 握手都会下发），
		// 提供下载便于用户导入系统信任库，消除浏览器警告并让 iframe 内嵌可用。
		api.GET("/cert", s.handleCert)
		// 证书指纹：客户端首次连接自签服务器时用于「信任首次使用」（TOFU）核对。
		api.GET("/fingerprint", s.handleFingerprint)
		api.GET("/status", s.handleStatus)
		api.POST("/setup", s.handleSetup)
		api.GET("/avatar/:id", s.handleGetAvatar)
		api.POST("/register", s.ipLimit(s.registerIP, "注册请求过于频繁，请稍后再试"), s.handleRegister)
		api.POST("/register/send-code", s.ipLimit(s.sendCodeIP, "验证码发送过于频繁，请稍后再试"), s.handleSendRegisterCode)
		api.GET("/settings/public", s.handlePublicSettings)
		api.POST("/login", s.ipLimit(s.loginIP, "登录请求过于频繁，请稍后再试"), s.handleLogin)
		// 退出登录：清除服务端下发的 HttpOnly 会话 Cookie（前端无法自行清除）。
		api.POST("/logout", s.handleLogout)
		api.POST("/reset/send-code", s.ipLimit(s.sendCodeIP, "验证码发送过于频繁，请稍后再试"), s.handleSendResetCode)
		api.POST("/reset", s.ipLimit(s.resetIP, "请求过于频繁，请稍后再试"), s.handleResetPassword)

		// 登录用户
		authed := api.Group("", s.authMiddleware())
		{
			authed.GET("/me", s.handleMe)
			authed.PUT("/me", s.handleUpdateMe)
			authed.POST("/me/avatar", s.handleUploadAvatar)
			// 密码条目统一走端到端加密的 Vault 协议（整库上传/下载），不存在明文接口。
			authed.GET("/vault", s.handleGetVault)
			authed.PUT("/vault", s.handlePutVault)
			authed.PUT("/vault-key", s.handlePutVaultKey)
			// 旧数据迁移专用：返回历史上由服务端静态密钥加密的明文，迁移完成后不再返回数据。
			authed.GET("/vault/legacy", s.handleGetLegacy)
			// 密码重置后放弃旧密码库：清空本账号全部条目密文并重置 vault key（见 handleDeleteVault）。
			authed.DELETE("/vault", s.handleDeleteVault)
			// 置顶同步开关（账号级）：开启后置顶作为密码库数据参与多端同步；
			// 关闭时桌面端置顶按设备保存、网页端按账号保存。飞牛网关只转发 GET/POST，
			// 写入口同时提供 POST。
			authed.GET("/vault/pin-sync", s.handleGetVaultPinSync)
			authed.PUT("/vault/pin-sync", s.handlePutVaultPinSync)
			authed.POST("/vault/pin-sync", s.handlePutVaultPinSync)

			// —— 网关兼容入口（POST 等价路径）——
			// 飞牛统一网关只转发 GET/POST：PUT/DELETE 会被网关自身接管并返回其首页（HTTP 200 非 JSON），
			// 前端表现为「接口返回了非预期内容」。因此所有写操作额外提供 POST 入口；
			// 直连端口时原有 PUT/DELETE 仍然可用（桌面客户端沿用）。
			authed.POST("/vault", s.handlePutVault)
			authed.POST("/vault/delete", s.handleDeleteVault)
			authed.POST("/vault-key", s.handlePutVaultKey)
			authed.POST("/me/update", s.handleUpdateMe)

			// 管理员
			admin := authed.Group("", s.adminMiddleware())
			{
				admin.GET("/users", s.handleListUsers)
				admin.POST("/users", s.handleCreateUser)
				admin.POST("/users/import", s.handleImportUsers)
				admin.DELETE("/users/:id", s.handleDeleteUser)
				admin.PUT("/users/:id", s.handleUpdateUser)
				admin.PUT("/users/:id/status", s.handleUpdateUserStatus)
				admin.GET("/logs", s.handleListLogs)
				admin.GET("/settings", s.handleGetSettings)
				admin.PUT("/settings", s.handleUpdateSettings)
				admin.POST("/settings/test-email", s.handleTestEmail)
				admin.GET("/settings/export", s.handleExportSettings)
				admin.POST("/settings/import", s.handleImportSettings)

				// 网关兼容入口：用户管理写操作（以查询参数传 id，避免与 /users/import 路由冲突）。
				admin.POST("/settings/update", s.handleUpdateSettings)
				admin.POST("/users/update", withQueryID(s.handleUpdateUser))
				admin.POST("/users/delete", withQueryID(s.handleDeleteUser))
				admin.POST("/users/status", withQueryID(s.handleUpdateUserStatus))
			}
		}
	}
}

// ---- 中间件 ----

// securityHeadersMiddleware 下发基础安全响应头。
// 仅在**真正的 TLS 连接**上下发 HSTS（而非"配置了证书"就下发）：飞牛统一网关
// 经 unix socket 以明文 HTTP 转发应用响应，此时若把 HSTS 透传给浏览器，会以
// NAS 主机名记录长达一年的强制 HTTPS，波及该主机上的其他服务与子域。
// 注意：不下发 X-Frame-Options——本应用需要被 fnOS 桌面以 iframe 形式内嵌
// （应用入口与 fnOS 桌面不同源），DENY/SAMEORIGIN 都会阻止该集成。
func securityHeadersMiddleware(cfg config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("Referrer-Policy", "no-referrer")
		if c.Request.TLS != nil {
			c.Header("Strict-Transport-Security", "max-age=31536000")
		}
		c.Next()
	}
}

// bodyLimitMiddleware 限制请求体大小，防止超大请求耗尽内存与磁盘。
func bodyLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Body != nil {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxJSONBody)
		}
		c.Next()
	}
}

// accessLogMiddleware 把每个 API 请求（方法/路径/状态/耗时）记入标准日志。
// 起因：飞牛网关场景排查「请求是否真的到达密匣服务」全靠猜测；fpk 部署下
// stdout 会写入数据目录 info.log，打开日志即可直接看到每个请求。
func accessLogMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		log.Info("API %s %s -> %d (%s)",
			c.Request.Method, c.Request.URL.Path, c.Writer.Status(), time.Since(start).Round(time.Millisecond))
	}
}

// corsMiddleware 仅对显式配置在白名单中的来源下发跨域响应头。
// CORS_ORIGINS 为空时不下发任何跨域头，浏览器只允许同源访问（推荐默认）。
func (s *Server) corsMiddleware() gin.HandlerFunc {
	allowed := make(map[string]bool, len(s.Cfg.CORSOrigins))
	for _, origin := range s.Cfg.CORSOrigins {
		allowed[origin] = true
	}
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin != "" && allowed[origin] {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Auth-Token")
			c.Header("Access-Control-Allow-Credentials", "true")
			c.Header("Access-Control-Max-Age", "600")
			c.Header("Vary", "Origin")
		}
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

// ipLimit 按客户端 IP 做限流。
func (s *Server) ipLimit(l *ratelimit.Limiter, msg string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !l.Allow(clientIP(c)) {
			c.Header("Retry-After", strconv.Itoa(int(l.RetryAfter(clientIP(c)).Seconds())+1))
			writeJSON(c, http.StatusTooManyRequests, gin.H{"error": msg})
			c.Abort()
			return
		}
		c.Next()
	}
}

// authTokenFromRequest 按优先级从请求中提取 JWT。
// 顺序很重要：直连端口时走 Authorization；经飞牛统一网关时该头会被网关剥离，
// 因此依次回退到自定义头 X-Auth-Token 与 HttpOnly Cookie（网关不干预 Cookie）。
func authTokenFromRequest(c *gin.Context) string {
	if h := c.GetHeader("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	if h := strings.TrimSpace(c.GetHeader("X-Auth-Token")); h != "" {
		return h
	}
	if ck, err := c.Cookie(authCookieName); err == nil && ck != "" {
		return ck
	}
	return ""
}

// sessionCookiePath 依据请求路径推导 Cookie 作用域：
// 经网关访问时原始路径形如 /app/cryptbox/api/login → Path=/app/cryptbox
// （令牌不外泄给同一主机上的其他服务）；直连端口时为 /api/login → Path=/。
func sessionCookiePath(c *gin.Context) string {
	p := web.OriginalPath(c.Request)
	if p == "" {
		p = c.Request.URL.Path
	}
	if i := strings.Index(p, "/api/"); i > 0 {
		return p[:i]
	}
	return "/"
}

// setSessionCookie 在登录成功后下发 HttpOnly 会话 Cookie。
// 网关会剥离 Authorization 头，Cookie 是内嵌场景下唯一可靠的凭据通道。
func setSessionCookie(c *gin.Context, token string) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     authCookieName,
		Value:    token,
		Path:     sessionCookiePath(c),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   c.Request.TLS != nil,
		MaxAge:   int(authCookieMaxAge.Seconds()),
	})
}

func clearSessionCookie(c *gin.Context) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     authCookieName,
		Value:    "",
		Path:     sessionCookiePath(c),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func (s *Server) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 仅认自定义账号密码签发的 JWT（不使用飞牛网关 X-Trim 头做强制验证），
		// 凭据可来自 Authorization 头、X-Auth-Token 头或会话 Cookie。
		if tok := authTokenFromRequest(c); tok != "" {
			if claims, err := auth.ParseToken(s.Cfg.JWTSecret, tok); err == nil {
				// 每请求回查角色、状态与令牌版本：
				//   · status != active → 停用即时生效；
				//   · token_version 不匹配 → 改密码后旧令牌立即失效（PT-06）。
				var role, status string
				var tokenVer int64
				if err := s.DB.QueryRow(`SELECT role, status, COALESCE(token_version, 0) FROM users WHERE id = ?`, claims.UserID).Scan(&role, &status, &tokenVer); err == nil &&
					status == "active" && tokenVer == claims.TokenVer {
					claims.Role = role
					c.Set("claims", claims)
					c.Next()
					return
				}
			}
		}

		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		c.Abort()
	}
}

func (s *Server) adminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		role := currentClaims(c).Role
		if role != "admin" && role != "superadmin" {
			c.JSON(http.StatusForbidden, gin.H{"error": "需要管理员权限"})
			c.Abort()
			return
		}
		c.Next()
	}
}

func currentClaims(c *gin.Context) *auth.Claims {
	v, _ := c.Get("claims")
	return v.(*auth.Claims)
}

// withQueryID 让「以查询参数传 id」的 POST 兼容入口复用原有按路径参数解析的处理器：
// 若路径中没有 :id 而查询串带 id，则注入到 c.Params。
// 采用查询参数而非 /users/:id/... 是为了避免与既有 /users/import 静态路由冲突。
func withQueryID(h gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Param("id") == "" {
			if id := strings.TrimSpace(c.Query("id")); id != "" {
				c.Params = append(c.Params, gin.Param{Key: "id", Value: id})
			}
		}
		h(c)
	}
}

// writeJSON / readJSON 保持与旧版一致的响应行为。
func writeJSON(c *gin.Context, status int, v interface{}) {
	c.JSON(status, v)
}

func readJSON(c *gin.Context, v interface{}) error {
	return json.NewDecoder(c.Request.Body).Decode(v)
}

// ---- 公开接口 ----

func (s *Server) handleHealth(c *gin.Context) {
	writeJSON(c, http.StatusOK, gin.H{"status": "ok", "time": time.Now().Format(time.RFC3339)})
}

// handleStatus 返回是否已初始化（是否已有用户）。
func (s *Server) handleStatus(c *gin.Context) {
	resp := gin.H{
		"initialized": db.IsInitialized(s.DB),
		// build 为版本号的短摘要：前端据此判断"页面是否比服务端旧"以自动刷新，
		// 未认证请求不暴露精确版本号（降低版本指纹信息暴露）。
		"build": version.BuildTag(),
	}
	// 已持有效令牌时附带精确版本号（界面页脚/关于页展示用）。
	if claims, err := auth.ParseToken(s.Cfg.JWTSecret, authTokenFromRequest(c)); err == nil && claims.UserID > 0 {
		resp["version"] = version.Version
	}
	writeJSON(c, http.StatusOK, resp)
}

// handleCert 下载当前启用的 TLS 证书（PEM）。
// 用途：用户将自签证书导入系统「受信任的根证书颁发机构」后，
// 浏览器不再弹证书警告，iframe 内嵌打开也不再被拦截。
// 证书本身是公开信息（TLS 握手时即下发），因此无需鉴权。
func (s *Server) handleCert(c *gin.Context) {
	if !s.Cfg.TLSEnabled() {
		writeJSON(c, http.StatusNotFound, gin.H{"error": "当前服务未启用 HTTPS，无证书可下载"})
		return
	}
	data, err := os.ReadFile(s.Cfg.TLSCert)
	if err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "读取证书失败"})
		return
	}
	c.Header("Content-Disposition", `attachment; filename="cryptbox.crt"`)
	c.Data(http.StatusOK, "application/x-x509-ca-cert", data)
}

// handleFingerprint 返回当前启用证书的 SHA-256 指纹（整证书 DER + SPKI 两种）。
// 用途：客户端连接自签服务器时，本地从 TLS 握手取到对端证书并计算指纹，
// 再把本接口返回的指纹作为「用户核对提示」的辅助信息（若两者不一致，说明
// 中间存在代理或伪造节点）。证书是公开信息（TLS 握手时即下发），无需鉴权。
func (s *Server) handleFingerprint(c *gin.Context) {
	if !s.Cfg.TLSEnabled() {
		writeJSON(c, http.StatusNotFound, gin.H{"error": "当前服务未启用 HTTPS，无证书指纹"})
		return
	}
	certFP, spkiFP, err := tlsutil.Fingerprints(s.Cfg.TLSCert)
	if err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "读取证书失败"})
		return
	}
	writeJSON(c, http.StatusOK, gin.H{
		"algorithm":   "SHA-256",
		"fingerprint": certFP,
		"spki":        spkiFP,
	})
}

// handleSetup 首次设置超级管理员账号（系统无用户时）。
func (s *Server) handleSetup(c *gin.Context) {
	var req struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		VaultKeyEnc string `json:"vault_key_enc"`
		KdfSalt     string `json:"kdf_salt"`
	}
	if err := readJSON(c, &req); err != nil {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "用户名不能为空"})
		return
	}
	// 超级管理员是最高权限账号，套用更严的口令要求（长度 + 复杂度）。
	if err := auth.ValidateSuperAdminPassword(s.DB, req.Password); err != nil {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "hash error"})
		return
	}
	// 原子初始化：仅当系统中尚无任何用户时才创建，避免并发请求重复初始化。
	id, created, err := db.SetupAdminIfEmpty(s.DB, req.Username, hash, "", strings.TrimSpace(req.KdfSalt))
	if err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	if !created {
		writeJSON(c, http.StatusConflict, gin.H{"error": "系统已初始化"})
		return
	}
	// 端到端加密：记录浏览器端用 master key 加密后的 vault key 密文。
	if req.VaultKeyEnc != "" {
		if _, err := s.DB.Exec(`UPDATE users SET vault_key_enc = ? WHERE id = ?`, req.VaultKeyEnc, id); err != nil {
			writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
	}
	token, _ := auth.GenerateToken(s.Cfg.JWTSecret, id, req.Username, "superadmin", db.TokenVersion(s.DB, id))
	setSessionCookie(c, token)
	log.LogAction(s.DB, id, req.Username, "setup", "初始化超级管理员", clientIP(c))
	writeJSON(c, http.StatusOK, gin.H{"token": token, "username": req.Username, "role": "superadmin", "avatar": avatarName(id)})
}

func (s *Server) handleRegister(c *gin.Context) {
	var req struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		Email       string `json:"email"`
		Code        string `json:"code"`
		VaultKeyEnc string `json:"vault_key_enc"`
		KdfSalt     string `json:"kdf_salt"`
	}
	if err := readJSON(c, &req); err != nil {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	req.Email = strings.TrimSpace(req.Email)
	if req.Username == "" {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "用户名不能为空"})
		return
	}
	if !auth.AllowRegistration(s.DB) {
		writeJSON(c, http.StatusForbidden, gin.H{"error": "注册未开放，请联系管理员"})
		return
	}
	if err := auth.ValidatePassword(s.DB, req.Password); err != nil {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Email == "" {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "请填写邮箱"})
		return
	}
	if !strings.Contains(req.Email, "@") || !strings.Contains(req.Email, ".") {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "邮箱格式不正确"})
		return
	}
	if !auth.CheckVerification(s.DB, req.Email, req.Code, "register") {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "邮箱验证码错误或已过期"})
		return
	}
	var exists int
	if err := s.DB.QueryRow(`SELECT COUNT(1) FROM users WHERE username = ?`, req.Username).Scan(&exists); err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	if exists > 0 {
		writeJSON(c, http.StatusConflict, gin.H{"error": "用户名已存在"})
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "hash error"})
		return
	}
	id, err := db.FindNextUserID(s.DB)
	if err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	_, err = s.DB.Exec(`INSERT INTO users (id, username, password_hash, role, status, email, vault_key_enc, kdf_salt) VALUES (?, ?, ?, 'user', 'active', ?, ?, ?)`, id, req.Username, hash, req.Email, req.VaultKeyEnc, strings.TrimSpace(req.KdfSalt))
	if err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	token, _ := auth.GenerateToken(s.Cfg.JWTSecret, id, req.Username, "user", db.TokenVersion(s.DB, id))
	setSessionCookie(c, token)
	writeJSON(c, http.StatusOK, gin.H{"token": token, "username": req.Username, "role": "user", "avatar": avatarName(id)})
}

func (s *Server) handleLogin(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := readJSON(c, &req); err != nil {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	login := strings.TrimSpace(req.Username)
	lockKey := strings.ToLower(login)
	// 账号维度失败锁定：抵御针对单一账号的口令暴力破解。
	if s.loginLock.Locked(lockKey) {
		writeJSON(c, http.StatusTooManyRequests, gin.H{"error": "登录失败次数过多，请 15 分钟后再试"})
		return
	}
	var (
		id          int64
		uname       string
		hash        string
		role        string
		status      string
		vaultKeyEnc string
		kdfSalt     string
	)
	err := s.DB.QueryRow(`SELECT id, username, password_hash, role, status, COALESCE(vault_key_enc, ''), COALESCE(kdf_salt, '') FROM users WHERE username = ? OR email = ?`, login, login).Scan(&id, &uname, &hash, &role, &status, &vaultKeyEnc, &kdfSalt)
	if err == sql.ErrNoRows || (err == nil && !auth.CheckPassword(hash, req.Password)) {
		s.loginLock.Fail(lockKey)
		log.LogAction(s.DB, 0, login, "login_failed", "登录失败", clientIP(c))
		writeJSON(c, http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
		return
	}
	if err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	if status != "active" {
		writeJSON(c, http.StatusForbidden, gin.H{"error": "账号已被停用"})
		return
	}
	s.loginLock.Reset(lockKey)
	log.LogAction(s.DB, id, uname, "login", "用户登录", clientIP(c))
	token, _ := auth.GenerateToken(s.Cfg.JWTSecret, id, uname, role, db.TokenVersion(s.DB, id))
	setSessionCookie(c, token)
	writeJSON(c, http.StatusOK, gin.H{"token": token, "username": uname, "role": role, "avatar": avatarName(id), "vault_key_enc": vaultKeyEnc, "kdf_salt": kdfSalt})
}

// handleLogout 退出登录：清除会话 Cookie（HttpOnly，只能由服务端清除）。
func (s *Server) handleLogout(c *gin.Context) {
	clearSessionCookie(c)
	writeJSON(c, http.StatusOK, gin.H{"status": "ok"})
}

// handleDeleteVault 清空当前用户的密码库并重置 vault key。
//
// 场景：用户通过「忘记密码」重置密码后，服务端保存的 vault_key_enc 仍由旧密码
// 派生的 master key 包裹，新密码无法解开。用户可选择：
//  1. 在解锁界面输入旧密码恢复（客户端用旧 master key 解开旧 vault key 后用新密码重新包裹，数据无损）；
//  2. 调用本接口放弃旧数据：清空条目密文并置空 vault_key_enc，下次解锁时自动生成新 vault key。
//
// 仅影响当前登录用户自己的数据。
func (s *Server) handleDeleteVault(c *gin.Context) {
	claims := currentClaims(c)
	if _, err := s.DB.Exec(`DELETE FROM entries WHERE user_id = ?`, claims.UserID); err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	if _, err := s.DB.Exec(`UPDATE users SET vault_key_enc = '' WHERE id = ?`, claims.UserID); err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	log.LogAction(s.DB, claims.UserID, claims.Username, "reset_vault", "清空密码库并重置 vault key", clientIP(c))
	writeJSON(c, http.StatusOK, gin.H{"status": "ok"})
}

// handlePutVaultKey 上传端到端加密的 vault key（用 master key 加密后的密文）。
func (s *Server) handlePutVaultKey(c *gin.Context) {
	claims := currentClaims(c)
	var req struct {
		VaultKeyEnc string `json:"vault_key_enc"`
	}
	if err := readJSON(c, &req); err != nil {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	if req.VaultKeyEnc == "" {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "vault_key_enc 不能为空"})
		return
	}
	if _, err := s.DB.Exec(`UPDATE users SET vault_key_enc = ? WHERE id = ?`, req.VaultKeyEnc, claims.UserID); err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	writeJSON(c, http.StatusOK, gin.H{"ok": true})
}

func (s *Server) handleMe(c *gin.Context) {
	claims := currentClaims(c)
	var username, email, vaultKeyEnc, kdfSalt string
	_ = s.DB.QueryRow(`SELECT username, email, COALESCE(vault_key_enc, ''), COALESCE(kdf_salt, '') FROM users WHERE id = ?`, claims.UserID).Scan(&username, &email, &vaultKeyEnc, &kdfSalt)
	writeJSON(c, http.StatusOK, gin.H{
		"id":            claims.UserID,
		"username":      username,
		"email":         email,
		"avatar":        avatarName(claims.UserID),
		"role":          claims.Role,
		"vault_key_enc": vaultKeyEnc,
		"kdf_salt":      kdfSalt,
		// 已认证请求返回精确版本号，供界面页脚/关于页展示。
		"version": version.Version,
	})
}

// recycleDays 返回回收站保留天数（默认 30）。
func recycleDays(database *sql.DB) int {
	if v := db.GetMeta(database, "recycle_days"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 30
}

// defaultLanguage 返回服务端默认语言（默认 zh-CN）。
func defaultLanguage(database *sql.DB) string {
	if v := db.GetMeta(database, "default_language"); v != "" {
		return v
	}
	return "zh-CN"
}

// purgeExpiredTrash 删除超过保留天数的墓碑条目（默认 30 天）。
func (s *Server) purgeExpiredTrash(userID int64) {
	threshold := time.Now().AddDate(0, 0, -recycleDays(s.DB)).Format(time.RFC3339)
	_, _ = s.DB.Exec(`DELETE FROM entries WHERE user_id = ? AND deleted = 1 AND updated_at < ?`, userID, threshold)
}

// ---- 桌面客户端同步（整体上传/下载） ----

func (s *Server) handleGetVault(c *gin.Context) {
	claims := currentClaims(c)
	// 下载前清理回收站中超过保留天数的墓碑条目。
	s.purgeExpiredTrash(claims.UserID)
	list, err := s.listEntriesAll(claims.UserID)
	if err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	// pin_sync 告知客户端当前账号的「置顶参与同步」开关：
	// 开启时客户端应采纳服务端置顶状态，关闭时应保留本机置顶（见各端同步实现）。
	pinSync, err := s.userPinSync(claims.UserID)
	if err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	writeJSON(c, http.StatusOK, gin.H{"entries": list, "pin_sync": pinSync})
}

func (s *Server) handlePutVault(c *gin.Context) {
	claims := currentClaims(c)
	var req struct {
		Entries []db.Entry `json:"entries"`
	}
	if err := readJSON(c, &req); err != nil {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	if err := s.replaceEntries(claims.UserID, req.Entries); err != nil {
		log.LogAction(s.DB, claims.UserID, claims.Username, "upload_vault_failed", "上传密码库失败: "+err.Error(), clientIP(c))
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "保存失败，请重试"})
		return
	}
	log.LogAction(s.DB, claims.UserID, claims.Username, "upload_vault", "上传密码库 "+strconv.Itoa(len(req.Entries))+" 条", clientIP(c))
	writeJSON(c, http.StatusOK, gin.H{"status": "ok"})
}

// userPinSync 读取账号级「置顶参与同步」开关（默认关闭）。
func (s *Server) userPinSync(userID int64) (bool, error) {
	var v int
	if err := s.DB.QueryRow(`SELECT pin_sync FROM users WHERE id = ?`, userID).Scan(&v); err != nil {
		return false, err
	}
	return v == 1, nil
}

// setUserPinSync 写入账号级「置顶参与同步」开关。
func (s *Server) setUserPinSync(userID int64, enabled bool) error {
	v := 0
	if enabled {
		v = 1
	}
	_, err := s.DB.Exec(`UPDATE users SET pin_sync = ? WHERE id = ?`, v, userID)
	return err
}

// handleGetVaultPinSync 返回当前账号的「置顶参与同步」开关状态。
func (s *Server) handleGetVaultPinSync(c *gin.Context) {
	claims := currentClaims(c)
	enabled, err := s.userPinSync(claims.UserID)
	if err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	writeJSON(c, http.StatusOK, gin.H{"pin_sync": enabled})
}

// handlePutVaultPinSync 修改当前账号的「置顶参与同步」开关。
// 开启后：置顶作为密码库数据参与多端同步（最后上传者生效）；
// 关闭时：桌面端置顶按设备各自保存，网页端置顶按账号保存，互不影响。
func (s *Server) handlePutVaultPinSync(c *gin.Context) {
	claims := currentClaims(c)
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if err := readJSON(c, &req); err != nil || req.Enabled == nil {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	if err := s.setUserPinSync(claims.UserID, *req.Enabled); err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	log.LogAction(s.DB, claims.UserID, claims.Username, "update_pin_sync", "置顶同步开关: "+strconv.FormatBool(*req.Enabled), clientIP(c))
	writeJSON(c, http.StatusOK, gin.H{"pin_sync": *req.Enabled})
}

// handleGetLegacy 返回历史上由服务端静态密钥加密的条目明文，仅用于一次性迁移到端到端加密。
// 迁移完成后条目已改为 vault key 加密，解密失败即被跳过，该接口最终返回空列表。
func (s *Server) handleGetLegacy(c *gin.Context) {
	claims := currentClaims(c)
	list := []db.Entry{}
	if len(s.EncKey) == 0 {
		writeJSON(c, http.StatusOK, gin.H{"entries": list})
		return
	}
	rows, err := s.DB.Query(`SELECT id, uuid, sort_order, title, username, url, category, password_enc, notes_enc, created_at, updated_at, deleted, pinned FROM entries WHERE user_id = ? ORDER BY sort_order ASC, id ASC`, claims.UserID)
	if err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	defer rows.Close()
	for rows.Next() {
		var e db.Entry
		var pwEnc, notesEnc string
		var deleted int
		var pinned bool
		if err := rows.Scan(&e.ID, &e.UUID, &e.SortOrder, &e.Title, &e.Username, &e.URL, &e.Category, &pwEnc, &notesEnc, &e.CreatedAt, &e.UpdatedAt, &deleted, &pinned); err != nil {
			writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
		e.Pinned = &pinned
		pw, err := crypto.AESDecryptString(s.EncKey, pwEnc)
		if err != nil {
			continue // 已是端到端密文，跳过
		}
		notes := ""
		if notesEnc != "" {
			if v, err := crypto.AESDecryptString(s.EncKey, notesEnc); err == nil {
				notes = v
			}
		}
		e.Password = pw
		e.Notes = notes
		e.Deleted = deleted != 0
		list = append(list, e)
	}
	writeJSON(c, http.StatusOK, gin.H{"entries": list})
}

// ---- 用户管理（仅管理员） ----

func (s *Server) handleListUsers(c *gin.Context) {
	rows, err := s.DB.Query(`SELECT id, username, email, role, status, created_at FROM users ORDER BY id`)
	if err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	defer rows.Close()
	list := []db.User{}
	for rows.Next() {
		var u db.User
		var created string
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.Role, &u.Status, &created); err != nil {
			writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
		u.CreatedAt = created
		u.Avatar = avatarName(u.ID)
		list = append(list, u)
	}
	writeJSON(c, http.StatusOK, gin.H{"users": list})
}

func (s *Server) handleCreateUser(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Email    string `json:"email"`
		Role     string `json:"role"`
	}
	if err := readJSON(c, &req); err != nil {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	req.Email = strings.TrimSpace(req.Email)
	if req.Username == "" || len(req.Password) < 6 {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "用户名不能为空，密码至少 6 位"})
		return
	}
	if req.Email == "" {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "邮箱不能为空"})
		return
	}
	if req.Role != "admin" && req.Role != "user" {
		req.Role = "user"
	}
	var exists int
	if err := s.DB.QueryRow(`SELECT COUNT(1) FROM users WHERE username = ?`, req.Username).Scan(&exists); err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	if exists > 0 {
		writeJSON(c, http.StatusConflict, gin.H{"error": "用户名已存在"})
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "hash error"})
		return
	}
	id, err := db.FindNextUserID(s.DB)
	if err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	_, err = s.DB.Exec(`INSERT INTO users (id, username, password_hash, role, status, email) VALUES (?, ?, ?, ?, 'active', ?)`, id, req.Username, hash, req.Role, req.Email)
	if err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	claims := currentClaims(c)
	log.LogAction(s.DB, claims.UserID, claims.Username, "create_user", "添加用户 "+req.Username, clientIP(c))
	writeJSON(c, http.StatusOK, gin.H{"status": "ok"})
}

// handleImportUsers 批量导入用户（CSV）。表头需含用户名、密码列，邮箱、角色可选；
// 用户名已存在或密码不足 6 位的行跳过，返回导入与跳过条数。
func (s *Server) handleImportUsers(c *gin.Context) {
	claims := currentClaims(c)
	var req struct {
		CSV string `json:"csv"`
	}
	if err := readJSON(c, &req); err != nil {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	users, err := csv.ParseCSVUsers([]byte(req.CSV))
	if err != nil {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	count, skipped := 0, 0
	for _, u := range users {
		username := strings.TrimSpace(u.Username)
		password := strings.TrimSpace(u.Password)
		if username == "" || len(password) < 6 {
			skipped++
			continue
		}
		role := "user"
		rl := strings.TrimSpace(u.Role)
		if rl == "admin" || rl == "管理员" || rl == "管理員" {
			role = "admin"
		}
		var exists int
		if err := s.DB.QueryRow(`SELECT COUNT(1) FROM users WHERE username = ?`, username).Scan(&exists); err != nil {
			writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
		if exists > 0 {
			skipped++
			continue
		}
		hash, err := auth.HashPassword(password)
		if err != nil {
			writeJSON(c, http.StatusInternalServerError, gin.H{"error": "hash error"})
			return
		}
		id, err := db.FindNextUserID(s.DB)
		if err != nil {
			writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
		if _, err := s.DB.Exec(`INSERT INTO users (id, username, password_hash, role, status, email) VALUES (?, ?, ?, ?, 'active', ?)`,
			id, username, hash, role, strings.TrimSpace(u.Email)); err != nil {
			writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
		count++
	}
	log.LogAction(s.DB, claims.UserID, claims.Username, "import_users", "导入用户 "+strconv.Itoa(count)+" 条", clientIP(c))
	writeJSON(c, http.StatusOK, gin.H{"count": count, "skipped": skipped})
}

func (s *Server) handleDeleteUser(c *gin.Context) {
	claims := currentClaims(c)
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	target, err := s.getUser(id)
	if err == sql.ErrNoRows {
		writeJSON(c, http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}
	if err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	if !auth.CanManageUser(claims.Role, target.Role) {
		writeJSON(c, http.StatusForbidden, gin.H{"error": "无权限操作该用户"})
		return
	}
	if id == claims.UserID {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "不能删除自己"})
		return
	}
	_, err = s.DB.Exec(`DELETE FROM entries WHERE user_id = ?`, id)
	if err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	_, err = s.DB.Exec(`DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	log.LogAction(s.DB, claims.UserID, claims.Username, "delete_user", "删除用户 "+target.Username, clientIP(c))
	writeJSON(c, http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) handleUpdateUserStatus(c *gin.Context) {
	claims := currentClaims(c)
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var req struct {
		Status string `json:"status"`
	}
	if err := readJSON(c, &req); err != nil {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	if req.Status != "active" && req.Status != "disabled" {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "status 必须为 active 或 disabled"})
		return
	}
	target, err := s.getUser(id)
	if err == sql.ErrNoRows {
		writeJSON(c, http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}
	if err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	if !auth.CanManageUser(claims.Role, target.Role) {
		writeJSON(c, http.StatusForbidden, gin.H{"error": "无权限操作该用户"})
		return
	}
	if id == claims.UserID && req.Status == "disabled" {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "不能停用自己"})
		return
	}
	_, err = s.DB.Exec(`UPDATE users SET status = ? WHERE id = ?`, req.Status, id)
	if err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	log.LogAction(s.DB, claims.UserID, claims.Username, "update_user_status", "设置用户 "+target.Username+" 状态为 "+req.Status, clientIP(c))
	writeJSON(c, http.StatusOK, gin.H{"status": "ok"})
}

// handleUpdateUser 管理员/超级管理员修改指定用户的信息。
func (s *Server) handleUpdateUser(c *gin.Context) {
	claims := currentClaims(c)
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	target, err := s.getUser(id)
	if err == sql.ErrNoRows {
		writeJSON(c, http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}
	if err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	if !auth.CanManageUser(claims.Role, target.Role) {
		writeJSON(c, http.StatusForbidden, gin.H{"error": "无权限操作该用户"})
		return
	}
	if id == claims.UserID {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "请通过「我的账号」修改自己"})
		return
	}
	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
		Role     string `json:"role"`
		Status   string `json:"status"`
	}
	if err := readJSON(c, &req); err != nil {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	username := strings.TrimSpace(req.Username)
	if username == "" {
		username = target.Username
	}
	role := target.Role
	if req.Role != "" {
		if req.Role != "admin" && req.Role != "user" {
			writeJSON(c, http.StatusBadRequest, gin.H{"error": "role 只能为 admin 或 user"})
			return
		}
		role = req.Role
	}
	status := target.Status
	if req.Status != "" {
		if req.Status != "active" && req.Status != "disabled" {
			writeJSON(c, http.StatusBadRequest, gin.H{"error": "status 必须为 active 或 disabled"})
			return
		}
		status = req.Status
	}
	if username != target.Username {
		var exists int
		if err := s.DB.QueryRow(`SELECT COUNT(1) FROM users WHERE username = ? AND id != ?`, username, id).Scan(&exists); err != nil {
			writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
		if exists > 0 {
			writeJSON(c, http.StatusConflict, gin.H{"error": "用户名已存在"})
			return
		}
	}
	// 邮箱留空时保留原值，避免管理员误提交清空用户邮箱（导致其无法找回密码）。
	email := strings.TrimSpace(req.Email)
	if email == "" {
		email = target.Email
	}
	if req.Password != "" {
		if len(req.Password) < 6 {
			writeJSON(c, http.StatusBadRequest, gin.H{"error": "密码至少 6 位"})
			return
		}
		hash, err := auth.HashPassword(req.Password)
		if err != nil {
			writeJSON(c, http.StatusInternalServerError, gin.H{"error": "hash error"})
			return
		}
		if _, err := s.DB.Exec(`UPDATE users SET username=?, email=?, password_hash=?, role=?, status=? WHERE id=?`, username, email, hash, role, status, id); err != nil {
			writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
		// 管理员改密后，该用户此前签发的所有令牌立即失效（PT-06）。
		_ = db.BumpTokenVersion(s.DB, id)
	} else {
		if _, err := s.DB.Exec(`UPDATE users SET username=?, email=?, role=?, status=? WHERE id=?`, username, email, role, status, id); err != nil {
			writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
	}
	log.LogAction(s.DB, claims.UserID, claims.Username, "update_user", "修改用户 "+target.Username, clientIP(c))
	writeJSON(c, http.StatusOK, gin.H{"status": "ok"})
}

// handleUpdateMe 用户修改自己的用户名、邮箱与密码。
func (s *Server) handleUpdateMe(c *gin.Context) {
	claims := currentClaims(c)
	var req struct {
		Username        string `json:"username"`
		Email           string `json:"email"`
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
		KdfSalt         string `json:"kdf_salt"`
		VaultKeyEnc     string `json:"vault_key_enc"`
	}
	if err := readJSON(c, &req); err != nil {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	username := strings.TrimSpace(req.Username)
	if username == "" {
		username = claims.Username
	}
	if username != claims.Username {
		var exists int
		if err := s.DB.QueryRow(`SELECT COUNT(1) FROM users WHERE username = ? AND id != ?`, username, claims.UserID).Scan(&exists); err != nil {
			writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
		if exists > 0 {
			writeJSON(c, http.StatusConflict, gin.H{"error": "用户名已存在"})
			return
		}
	}
	if req.NewPassword != "" {
		// 超级管理员账号沿用更严的口令要求（长度 + 复杂度）。
		var validator func(string) error
		if claims.Role == "superadmin" {
			validator = func(p string) error { return auth.ValidateSuperAdminPassword(s.DB, p) }
		} else {
			validator = func(p string) error { return auth.ValidatePassword(s.DB, p) }
		}
		if err := validator(req.NewPassword); err != nil {
			writeJSON(c, http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		var hash string
		if err := s.DB.QueryRow(`SELECT password_hash FROM users WHERE id = ?`, claims.UserID).Scan(&hash); err != nil {
			writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
		if !auth.CheckPassword(hash, req.CurrentPassword) {
			writeJSON(c, http.StatusBadRequest, gin.H{"error": "当前密码错误"})
			return
		}
	}

	// 一致性保护：密码或派生盐变更会改变主密钥，若账号已存在 vault_key_enc，
	// 必须同时提交用新主密钥重新加密的 vault_key_enc —— 否则旧密文将永久无法解密。
	// 客户端未解锁密码库时应拒绝改密（无法重新包裹密钥）。
	newSalt := strings.TrimSpace(req.KdfSalt)
	newVaultKey := strings.TrimSpace(req.VaultKeyEnc)
	var currentVaultKey string
	if err := s.DB.QueryRow(`SELECT COALESCE(vault_key_enc, '') FROM users WHERE id = ?`, claims.UserID).Scan(&currentVaultKey); err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	if strings.TrimSpace(currentVaultKey) != "" && (req.NewPassword != "" || newSalt != "") && newVaultKey == "" {
		writeJSON(c, http.StatusBadRequest, gin.H{
			"error": "修改密码需要同时提交重新加密的密码库密钥，请先解锁密码库后重试",
		})
		return
	}

	// 单事务写入，保证「密码 / 派生盐 / 密码库密钥」三者始终一致。
	tx, err := s.DB.Begin()
	if err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	defer func() { _ = tx.Rollback() }()

	if req.NewPassword != "" {
		newHash, err := auth.HashPassword(req.NewPassword)
		if err != nil {
			writeJSON(c, http.StatusInternalServerError, gin.H{"error": "hash error"})
			return
		}
		// 改密同时递增令牌版本：旧令牌全部失效（PT-06）。本次会话在提交后
		// 重新签发（见函数末尾），避免用户刚改完密码就被登出。
		if _, err := tx.Exec(`UPDATE users SET username=?, email=?, password_hash=?, token_version = COALESCE(token_version, 0) + 1 WHERE id=?`, username, req.Email, newHash, claims.UserID); err != nil {
			writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
	} else {
		if _, err := tx.Exec(`UPDATE users SET username=?, email=? WHERE id=?`, username, req.Email, claims.UserID); err != nil {
			writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
	}
	// 派生盐与密码库密钥必须成对更新（同一事务）。
	if newSalt != "" || newVaultKey != "" {
		if _, err := tx.Exec(`UPDATE users SET kdf_salt = ?, vault_key_enc = COALESCE(NULLIF(?, ''), vault_key_enc) WHERE id = ?`,
			newSalt, newVaultKey, claims.UserID); err != nil {
			writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
	}
	if err := tx.Commit(); err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	detail := "修改账号信息"
	if req.NewPassword != "" {
		detail = "修改密码"
	}
	log.LogAction(s.DB, claims.UserID, claims.Username, "update_me", detail, clientIP(c))
	resp := gin.H{"status": "ok"}
	// 改密后令牌版本已 +1，旧令牌即刻失效；这里为**当前会话**重新签发一个，
	// 并把新令牌回给前端（同时刷新 Cookie），避免用户被自己登出。
	if req.NewPassword != "" {
		if tok, err := auth.GenerateToken(s.Cfg.JWTSecret, claims.UserID, username, claims.Role, db.TokenVersion(s.DB, claims.UserID)); err == nil {
			setSessionCookie(c, tok)
			resp["token"] = tok
		}
	}
	writeJSON(c, http.StatusOK, resp)
}

// ---- 数据访问辅助 ----

// listEntriesAll 返回该用户的全部条目（含墓碑），用于同步 vault 上传/下载。
func (s *Server) listEntriesAll(userID int64) ([]db.Entry, error) {
	rows, err := s.DB.Query(`SELECT id, uuid, sort_order, title, username, url, category, password_enc, notes_enc, created_at, updated_at, deleted, pinned FROM entries WHERE user_id = ? ORDER BY pinned DESC, sort_order ASC, id ASC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []db.Entry{}
	for rows.Next() {
		var e db.Entry
		var pwEnc, notesEnc string
		var deleted int
		var pinned bool
		if err := rows.Scan(&e.ID, &e.UUID, &e.SortOrder, &e.Title, &e.Username, &e.URL, &e.Category, &pwEnc, &notesEnc, &e.CreatedAt, &e.UpdatedAt, &deleted, &pinned); err != nil {
			return nil, err
		}
		e.Pinned = &pinned
		// 端到端加密：密文由客户端用 vault key 加密，服务端不透明存储。
		e.Password = pwEnc
		e.Notes = notesEnc
		e.Deleted = deleted != 0
		list = append(list, e)
	}
	return list, rows.Err()
}

// normalizeEntryUUID 返回条目的规范 uuid（PT-04）：
//   - 合法 UUID → 统一小写后原样使用（客户端新版自带随机 v4）；
//   - 空/非法 → 按 UUIDv5(user_id, id) 分配确定性标识。
//
// 这样旧版客户端（不带 uuid）与新版客户端对同一条目得到相同标识，迁移幂等。
func normalizeEntryUUID(userID int64, e *db.Entry) string {
	u := strings.ToLower(strings.TrimSpace(e.UUID))
	if uuid.IsValid(u) {
		return u
	}
	return uuid.Deterministic(userID, e.ID)
}

func (s *Server) replaceEntries(userID int64, list []db.Entry) error {
	// 读取既有置顶状态（uuid 与 id 两个维度），用于「上传载荷未携带 pinned」的
	// 条目保留原状态（典型：关闭置顶同步的桌面端按设备上传）。
	storedPins := make(map[string]bool)
	rows, err := s.DB.Query(`SELECT uuid, id, pinned FROM entries WHERE user_id = ? AND pinned = 1`, userID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var u string
		var id, p int
		if err := rows.Scan(&u, &id, &p); err == nil && p == 1 {
			if u != "" {
				storedPins["u:"+u] = true
			}
			storedPins["i:"+strconv.Itoa(id)] = true
		}
	}
	rows.Close()
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM entries WHERE user_id = ?`, userID); err != nil {
		_ = tx.Rollback()
		return err
	}
	// 1) 规范化 uuid，并按 uuid 去重（同请求内重复时保留最后一条）。
	seenUUID := make(map[string]bool, len(list))
	deduped := make([]db.Entry, 0, len(list))
	for i := len(list) - 1; i >= 0; i-- {
		e := list[i]
		e.UUID = normalizeEntryUUID(userID, &e)
		if seenUUID[e.UUID] {
			continue
		}
		seenUUID[e.UUID] = true
		deduped = append(deduped, e)
	}
	// 还原为客户端提交的先后顺序。
	for i, j := 0, len(deduped)-1; i < j; i, j = i+1, j-1 {
		deduped[i], deduped[j] = deduped[j], deduped[i]
	}
	// 2) id 唯一化：uuid 才是条目身份，若不同 uuid 撞了同一个 id，
	//    直接丢弃会造成静默数据丢失，因此重新分配一个未占用的 id。
	maxID := int64(0)
	for _, e := range deduped {
		if e.ID > maxID {
			maxID = e.ID
		}
	}
	usedID := make(map[int64]bool, len(deduped))
	for i := range deduped {
		if deduped[i].ID <= 0 || usedID[deduped[i].ID] {
			maxID++
			deduped[i].ID = maxID
		}
		usedID[deduped[i].ID] = true
	}
	for _, e := range deduped {
		// 端到端加密：客户端已用 vault key 加密，服务端不透明存储。
		pwEnc := e.Password
		notesEnc := e.Notes
		deleted := 0
		if e.Deleted {
			deleted = 1
		}
		// 置顶：载荷携带该字段（网页端编辑 / 已开启置顶同步的桌面端）→ 采纳；
		// 未携带（关闭置顶同步的桌面端）→ 保留服务端已存状态，新条目视为未置顶。
		pinned := false
		if e.Pinned != nil {
			pinned = *e.Pinned
		} else {
			key := "u:" + e.UUID
			if e.UUID == "" {
				key = "i:" + strconv.FormatInt(e.ID, 10)
			}
			pinned = storedPins[key]
		}
		_, err = tx.Exec(`INSERT INTO entries (id, uuid, sort_order, user_id, title, username, url, category, password_enc, notes_enc, created_at, updated_at, deleted, pinned) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			e.ID, e.UUID, e.SortOrder, userID, e.Title, e.Username, e.URL, e.Category, pwEnc, notesEnc, e.CreatedAt, e.UpdatedAt, deleted, pinned)
		if err != nil {
			_ = tx.Rollback()
			// 主键 (user_id,id) 与唯一索引 (user_id,uuid) 均在上面去重过，
			// 正常不应再冲突；保留原始错误便于排查。
			return fmt.Errorf("写入条目 id=%d uuid=%s 失败: %w", e.ID, e.UUID, err)
		}
	}
	return tx.Commit()
}

// getUser 按 ID 查询用户。
func (s *Server) getUser(id int64) (*db.User, error) {
	var u db.User
	var created string
	err := s.DB.QueryRow(`SELECT id, username, email, role, status, created_at FROM users WHERE id = ?`, id).
		Scan(&u.ID, &u.Username, &u.Email, &u.Role, &u.Status, &created)
	if err != nil {
		return nil, err
	}
	u.CreatedAt = created
	u.Avatar = avatarName(u.ID)
	return &u, nil
}

// handleSendRegisterCode 发送注册验证码。
func (s *Server) handleSendRegisterCode(c *gin.Context) {
	var req struct {
		Email string `json:"email"`
	}
	if err := readJSON(c, &req); err != nil {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "邮箱不能为空"})
		return
	}
	if !auth.AllowRegistration(s.DB) {
		writeJSON(c, http.StatusForbidden, gin.H{"error": "注册未开放，请联系管理员"})
		return
	}
	// 邮箱维度限流：避免同一邮箱被反复触发发信。
	if !s.sendCodeEmail.Allow(strings.ToLower(req.Email)) {
		writeJSON(c, http.StatusTooManyRequests, gin.H{"error": "验证码发送过于频繁，请稍后再试"})
		return
	}
	if err := auth.SendVerifyCode(s.DB, s.EncKey, req.Email, "register"); err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	writeJSON(c, http.StatusOK, gin.H{"status": "ok"})
}

// handleSendResetCode 发送密码重置验证码。
// 无论邮箱是否已注册都返回同一响应，避免攻击者据此枚举有效邮箱。
func (s *Server) handleSendResetCode(c *gin.Context) {
	var req struct {
		Email string `json:"email"`
	}
	if err := readJSON(c, &req); err != nil {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "邮箱不能为空"})
		return
	}
	// 邮箱维度限流：同一邮箱在窗口内只允许少量发码请求。
	if !s.sendCodeEmail.Allow(strings.ToLower(req.Email)) {
		writeJSON(c, http.StatusTooManyRequests, gin.H{"error": "验证码发送过于频繁，请稍后再试"})
		return
	}
	var id int64
	err := s.DB.QueryRow(`SELECT id FROM users WHERE email = ?`, req.Email).Scan(&id)
	if err == nil {
		// 仅在邮箱真实存在时发信；失败也不向调用方暴露差异。
		_ = auth.SendVerifyCode(s.DB, s.EncKey, req.Email, "reset")
	}
	writeJSON(c, http.StatusOK, gin.H{"status": "ok"})
}

// handleResetPassword 重置密码。验证码一次性消费 + 邮箱维度尝试上限，
// 使 6 位数字验证码无法被在线穷举。
func (s *Server) handleResetPassword(c *gin.Context) {
	var req struct {
		Email    string `json:"email"`
		Code     string `json:"code"`
		Password string `json:"password"`
	}
	if err := readJSON(c, &req); err != nil {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "邮箱不能为空"})
		return
	}
	// 新口令沿用与改密一致的要求（长度 + 复杂度）。
	if err := auth.ValidatePassword(s.DB, req.Password); err != nil {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// 必须在校验之前消费配额，否则限流形同虚设。
	if !s.resetEmail.Allow(strings.ToLower(req.Email)) {
		writeJSON(c, http.StatusTooManyRequests, gin.H{"error": "验证码尝试次数过多，请 15 分钟后重新获取"})
		return
	}
	if !auth.CheckVerification(s.DB, req.Email, req.Code, "reset") {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "验证码错误或已过期"})
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "hash error"})
		return
	}
	// 邮件重置口令同样递增令牌版本：重置前泄露的令牌立即失效（PT-06）。
	res, err := s.DB.Exec(`UPDATE users SET password_hash = ?, token_version = COALESCE(token_version, 0) + 1 WHERE email = ?`, hash, req.Email)
	if err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeJSON(c, http.StatusNotFound, gin.H{"error": "该邮箱未注册"})
		return
	}
	log.LogAction(s.DB, 0, req.Email, "reset_password", "重置密码", clientIP(c))
	writeJSON(c, http.StatusOK, gin.H{"status": "ok"})
}

// handlePublicSettings 公开返回邮箱验证模式与站点信息（用于注册/找回密码页面及页脚）。
func (s *Server) handlePublicSettings(c *gin.Context) {
	writeJSON(c, http.StatusOK, gin.H{
		"email_verify_mode":        auth.EmailVerifyMode(s.DB),
		"allow_registration":       auth.AllowRegistration(s.DB),
		"password_min_length":      auth.PasswordMinLength(s.DB),
		"password_require_complex": auth.PasswordRequireComplex(s.DB),
		"default_language":         defaultLanguage(s.DB),
		"recycle":                  db.GetMeta(s.DB, "recycle") != "false",
		"site":                     db.LoadSiteConfig(s.DB),
	})
}

// handleGetSettings 返回系统设置（SMTP 配置 + 邮箱验证模式 + 站点信息）。
func (s *Server) handleGetSettings(c *gin.Context) {
	writeJSON(c, http.StatusOK, gin.H{
		"smtp":                     auth.LoadSMTPConfig(s.DB, s.EncKey),
		"smtp_enabled":             auth.SMTPEnabled(s.DB),
		"email_verify_mode":        auth.EmailVerifyMode(s.DB),
		"allow_registration":       db.GetMeta(s.DB, "allow_registration") == "true",
		"password_min_length":      auth.PasswordMinLength(s.DB),
		"password_require_complex": auth.PasswordRequireComplex(s.DB),
		"recycle":                  db.GetMeta(s.DB, "recycle") != "false",
		"recycle_days":             recycleDays(s.DB),
		"site":                     db.LoadSiteConfig(s.DB),
	})
}

// handleUpdateSettings 更新系统设置。
func (s *Server) handleUpdateSettings(c *gin.Context) {
	claims := currentClaims(c)
	var req struct {
		Host                   string         `json:"host"`
		Port                   int            `json:"port"`
		Username               string         `json:"username"`
		Password               string         `json:"password"`
		From                   string         `json:"from"`
		SSL                    bool           `json:"ssl"`
		Vendor                 string         `json:"vendor"`
		SMTPEnabled            *bool          `json:"smtp_enabled"`
		Mode                   string         `json:"mode"`
		AllowRegistration      *bool          `json:"allow_registration"`
		PasswordMinLength      int            `json:"password_min_length"`
		PasswordRequireComplex *bool          `json:"password_require_complex"`
		Recycle                *bool          `json:"recycle"`
		RecycleDays            int            `json:"recycle_days"`
		Site                   *db.SiteConfig `json:"site"`
	}
	if err := readJSON(c, &req); err != nil {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	if req.Mode != "" {
		if req.Mode != "code" && req.Mode != "link" && req.Mode != "none" {
			writeJSON(c, http.StatusBadRequest, gin.H{"error": "mode 必须为 code/link/none"})
			return
		}
		_ = db.SetMeta(s.DB, "email_verify_mode", req.Mode)
	}
	allowedVendor := map[string]bool{
		"qq": true, "126": true, "163": true, "gmail": true, "outlook": true, "custom": true,
	}
	if req.Vendor != "" {
		if !allowedVendor[req.Vendor] {
			writeJSON(c, http.StatusBadRequest, gin.H{"error": "vendor 非法"})
			return
		}
		_ = db.SetMeta(s.DB, "smtp_vendor", req.Vendor)
	}
	_ = db.SetMeta(s.DB, "smtp_host", req.Host)
	_ = db.SetMeta(s.DB, "smtp_port", strconv.Itoa(req.Port))
	_ = db.SetMeta(s.DB, "smtp_username", req.Username)
	_ = db.SetMeta(s.DB, "smtp_from", req.From)
	// SMTP 口令加密后落库（PT-07）；掩码值表示"保持原口令不变"。
	if req.Password != "" && req.Password != auth.MaskedSecret {
		enc, err := auth.EncryptSMTPPassword(s.EncKey, req.Password)
		if err != nil {
			writeJSON(c, http.StatusInternalServerError, gin.H{"error": "保存 SMTP 口令失败"})
			return
		}
		_ = db.SetMeta(s.DB, "smtp_password", enc)
	}
	if req.SSL {
		_ = db.SetMeta(s.DB, "smtp_ssl", "true")
	} else {
		_ = db.SetMeta(s.DB, "smtp_ssl", "false")
	}
	if req.SMTPEnabled != nil {
		if *req.SMTPEnabled {
			_ = db.SetMeta(s.DB, "smtp_enabled", "true")
		} else {
			_ = db.SetMeta(s.DB, "smtp_enabled", "false")
		}
	}
	if req.AllowRegistration != nil {
		if *req.AllowRegistration {
			_ = db.SetMeta(s.DB, "allow_registration", "true")
		} else {
			_ = db.SetMeta(s.DB, "allow_registration", "false")
		}
	}
	if req.PasswordMinLength > 0 {
		_ = db.SetMeta(s.DB, "password_min_length", strconv.Itoa(req.PasswordMinLength))
	}
	if req.PasswordRequireComplex != nil {
		if *req.PasswordRequireComplex {
			_ = db.SetMeta(s.DB, "password_require_complex", "true")
		} else {
			_ = db.SetMeta(s.DB, "password_require_complex", "false")
		}
	}
	if req.Recycle != nil {
		if *req.Recycle {
			_ = db.SetMeta(s.DB, "recycle", "true")
		} else {
			_ = db.SetMeta(s.DB, "recycle", "false")
		}
	}
	if req.RecycleDays > 0 {
		_ = db.SetMeta(s.DB, "recycle_days", strconv.Itoa(req.RecycleDays))
	}
	if req.Site != nil {
		_ = db.SetMeta(s.DB, "site_footer_text", req.Site.FooterText)
	}
	log.LogAction(s.DB, claims.UserID, claims.Username, "config_update", "更新系统设置", clientIP(c))
	writeJSON(c, http.StatusOK, gin.H{"status": "ok"})
}

// handleTestEmail 发送测试邮件，验证 SMTP 配置是否可用。
func (s *Server) handleTestEmail(c *gin.Context) {
	var req struct {
		Email string `json:"email"`
	}
	if err := readJSON(c, &req); err != nil {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	if req.Email == "" {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "email 不能为空"})
		return
	}
	if err := auth.SendHTMLEmail(s.DB, s.EncKey, req.Email, "密匣 CryPtBox 测试邮件", auth.TestEmailHTML()); err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	writeJSON(c, http.StatusOK, gin.H{"status": "ok"})
}

// handleExportSettings 导出系统配置（meta 中除 encryption_key 外的所有键值），供备份/迁移。
func (s *Server) handleExportSettings(c *gin.Context) {
	rows, err := s.DB.Query(`SELECT key, value FROM meta WHERE key != 'encryption_key' AND key != 'jwt_secret' ORDER BY key`)
	if err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	defer rows.Close()
	meta := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			continue
		}
		// 敏感字段掩码输出（PT-07）：导出件可能被分享/入库，不应携带可直接使用的口令。
		if k == "smtp_password" && v != "" {
			v = auth.MaskedSecret
		}
		meta[k] = v
	}
	writeJSON(c, http.StatusOK, gin.H{"meta": meta})
}

// importableMetaKeys 是允许通过「导入系统配置」写入的 meta 键白名单。
// 采用白名单而非黑名单：新增系统键值不会被旧版本导入逻辑意外覆盖，
// 且 encryption_key / jwt_secret 等密钥类字段天然不在其中。
var importableMetaKeys = map[string]bool{
	"email_verify_mode":        true,
	"allow_registration":       true,
	"password_min_length":      true,
	"password_require_complex": true,
	"recycle":                  true,
	"recycle_days":             true,
	"default_language":         true,
	"site_footer_text":         true,
	"smtp_host":                true,
	"smtp_port":                true,
	"smtp_username":            true,
	"smtp_password":            true,
	"smtp_from":                true,
	"smtp_ssl":                 true,
	"smtp_vendor":              true,
	"smtp_enabled":             true,
}

// clampIntMeta 对数值型配置做范围钳制，避免被写入极端值（如超大密码长度要求）导致功能不可用。
func clampIntMeta(key, v string) string {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return ""
	}
	switch key {
	case "password_min_length":
		if n < 6 {
			n = 6
		}
		if n > 128 {
			n = 128
		}
	case "recycle_days":
		if n < 1 {
			n = 1
		}
		if n > 3650 {
			n = 3650
		}
	}
	return strconv.Itoa(n)
}

// handleImportSettings 导入系统配置（仅写入白名单内的 meta 键值，密钥类字段永不可覆盖）。
func (s *Server) handleImportSettings(c *gin.Context) {
	var req struct {
		Meta map[string]string `json:"meta"`
	}
	if err := readJSON(c, &req); err != nil {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	if req.Meta == nil {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "meta 不能为空"})
		return
	}
	for k, v := range req.Meta {
		if !importableMetaKeys[k] {
			continue
		}
		// 掩码值表示"保持原值"：导入由本应用导出的配置文件时不应把口令改成 ******。
		if k == "smtp_password" && (v == auth.MaskedSecret || v == "") {
			continue
		}
		if k == "password_min_length" || k == "recycle_days" {
			v = clampIntMeta(k, v)
			if v == "" {
				continue
			}
		}
		if err := db.SetMeta(s.DB, k, v); err != nil {
			writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
	}
	claims := currentClaims(c)
	log.LogAction(s.DB, claims.UserID, claims.Username, "import_settings", "导入系统配置", clientIP(c))
	writeJSON(c, http.StatusOK, gin.H{"status": "ok"})
}

// handleListLogs 返回最近的操作日志（仅管理员）。
func (s *Server) handleListLogs(c *gin.Context) {
	rows, err := s.DB.Query(`SELECT id, user_id, username, action, detail, ip, created_at FROM logs ORDER BY id DESC LIMIT 999`)
	if err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	defer rows.Close()
	list := []db.LogEntry{}
	for rows.Next() {
		var e db.LogEntry
		var created string
		if err := rows.Scan(&e.ID, &e.UserID, &e.Username, &e.Action, &e.Detail, &e.IP, &created); err != nil {
			writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
		e.CreatedAt = created
		list = append(list, e)
	}
	writeJSON(c, http.StatusOK, gin.H{"logs": list})
}

// clientIP 从 gin.Context 提取客户端 IP（兼容网关 X-Forwarded-For）。
func clientIP(c *gin.Context) string {
	return log.ClientIP(c.Request)
}

// ---- 头像 ----

func avatarDir() string {
	return filepath.Join(config.DataDir(), "uploads", "avatars")
}

// findAvatar 返回指定用户头像文件的路径，不存在则返回空字符串。
func findAvatar(userID int64) string {
	matches, _ := filepath.Glob(filepath.Join(avatarDir(), strconv.FormatInt(userID, 10)+".*"))
	if len(matches) > 0 {
		return matches[0]
	}
	return ""
}

// avatarName 返回用户头像文件名（如 1.png），无头像返回空字符串。
func avatarName(userID int64) string {
	if p := findAvatar(userID); p != "" {
		return filepath.Base(p)
	}
	return ""
}

// handleGetAvatar 返回用户头像（公开）。
func (s *Server) handleGetAvatar(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.String(http.StatusNotFound, "not found")
		return
	}
	p := findAvatar(id)
	if p == "" {
		c.String(http.StatusNotFound, "not found")
		return
	}
	data, err := os.ReadFile(p)
	if err != nil {
		c.String(http.StatusNotFound, "not found")
		return
	}
	c.Header("Cache-Control", "no-cache")
	ext := strings.TrimPrefix(strings.ToLower(filepath.Ext(p)), ".")
	// SVG 可内嵌 <script>：对历史上传并残留的 svg 文件不再以可执行类型内联返回，
	// 一律强制下载，避免在同源上下文中执行任意 JavaScript。
	if ext == "svg" {
		c.Header("Content-Disposition", "attachment")
		c.Data(http.StatusOK, "application/octet-stream", data)
		return
	}
	ct := "image/" + ext
	if ext == "jpg" {
		ct = "image/jpeg"
	}
	c.Data(http.StatusOK, ct, data)
}

// detectImageExt 依据文件魔数判定真实图片类型，返回扩展名；无法识别返回空字符串。
// 不使用客户端声明的扩展名，避免「声称 png 实为其它内容」的绕过。
func detectImageExt(data []byte) string {
	switch {
	case len(data) >= 8 && bytes.Equal(data[:8], []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}):
		return "png"
	case len(data) >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF:
		return "jpg"
	case len(data) >= 6 && (bytes.Equal(data[:6], []byte("GIF87a")) || bytes.Equal(data[:6], []byte("GIF89a"))):
		return "gif"
	case len(data) >= 12 && bytes.Equal(data[:4], []byte("RIFF")) && bytes.Equal(data[8:12], []byte("WEBP")):
		return "webp"
	}
	return ""
}

// handleUploadAvatar 上传当前用户的头像（body: base64 数据 + 扩展名）。
func (s *Server) handleUploadAvatar(c *gin.Context) {
	claims := currentClaims(c)
	var req struct {
		Data string `json:"data"`
		Ext  string `json:"ext"`
	}
	if err := readJSON(c, &req); err != nil {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	data, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "图片数据无效"})
		return
	}
	if len(data) > 2*1024*1024 {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "图片不能超过 2MB"})
		return
	}
	// 以文件魔数判定真实类型，忽略客户端声明的扩展名。
	// SVG 已不再支持：其可内嵌脚本，作为同源资源返回会构成存储型 XSS。
	ext := detectImageExt(data)
	if ext == "" {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "不支持的图片格式（仅支持 PNG / JPG / GIF / WebP）"})
		return
	}
	if err := os.MkdirAll(avatarDir(), 0o755); err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	if old := findAvatar(claims.UserID); old != "" {
		_ = os.Remove(old)
	}
	filename := strconv.FormatInt(claims.UserID, 10) + "." + ext
	if err := os.WriteFile(filepath.Join(avatarDir(), filename), data, 0o644); err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	writeJSON(c, http.StatusOK, gin.H{"avatar": filename})
}
