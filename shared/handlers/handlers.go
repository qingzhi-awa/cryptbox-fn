// Package handlers 提供 Gin HTTP 处理器、路由注册与中间件。
package handlers

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	setupIPPerMinute       = 5
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
	setupIP       *ratelimit.Limiter
	resetIP       *ratelimit.Limiter
	resetEmail    *ratelimit.Limiter
	sendCodeIP    *ratelimit.Limiter
	sendCodeEmail *ratelimit.Limiter
}

// legacyMigrationDoneKeyPrefix 是 meta 表中"旧明文数据已迁移完成"标记的**键前缀**。
//
// 重要：标记必须**按用户**隔离，键形如 `legacy_migration_done:<user_id>`。
// 若用一个全局键（如早期的 `legacy_migration_done`），任一用户（哪怕是最普通的
// 用户）调用一次 POST /api/vault/legacy/done，就会把**全服务器所有用户**的
// legacy 迁移接口一起封死（410 Gone），导致其他人重置密码后永久无法迁移旧数据。
//
// 每个用户只有自己的 vault 需要迁移，因此标记天然是账号级的。
const legacyMigrationDoneKeyPrefix = "legacy_migration_done:"

// legacyMigrationKey 返回某用户的 legacy 迁移完成标记键（按 user_id 隔离）。
func legacyMigrationKey(userID int64) string {
	return legacyMigrationDoneKeyPrefix + strconv.FormatInt(userID, 10)
}

// legacyMigrationDone 判断该用户的旧数据迁移是否已完成。
//
// 兼容性：早期版本曾把标记写成**全局**键 `legacy_migration_done`。为不丢失那次
// 已经完成的迁移结论（升级后不应让已迁移用户重新看到 legacy 接口），这里同时
// 兼容识别该历史全局键——但**只读不写**，新标记一律写账号级键。
func (s *Server) legacyMigrationDone(userID int64) bool {
	if db.GetMeta(s.DB, legacyMigrationKey(userID)) == "1" {
		return true
	}
	return db.GetMeta(s.DB, "legacy_migration_done") == "1"
}

// markLegacyMigrationDone 落该用户的"迁移已完成"标记。
func (s *Server) markLegacyMigrationDone(userID int64, username string, ip string) error {
	if err := db.SetMeta(s.DB, legacyMigrationKey(userID), "1"); err != nil {
		return err
	}
	log.LogAction(s.DB, userID, username, "legacy_migrated", "旧明文数据迁移完成，已关闭该账号的 legacy 接口", ip)
	return nil
}

// legacyAPIRemoveVersion 是计划移除 legacy 明文迁移接口（GET /api/vault/legacy）的版本。
//
// 该接口会以**明文**返回服务端静态密钥可解的历史条目，只是过渡期的"一次性后门"。
// 迁移必须由客户端持有 vault key 时完成，服务端无法代办；为避免它无限期存在，
// 约定在 0.3.0 移除。届时仍未迁移的账号，其历史条目需在客户端重新录入。
const legacyAPIRemoveVersion = "0.3.0"

// userHasLegacyPlaintext 判断该账号是否仍有可用服务端静态密钥解密的历史条目。
// 逐条尝试解密，命中一条即返回（无需统计全部），用于管理侧"未迁移账号"提示。
func (s *Server) userHasLegacyPlaintext(userID int64) (bool, error) {
	if len(s.EncKey) == 0 {
		return false, nil
	}
	rows, err := s.DB.Query(`SELECT password_enc, notes_enc FROM entries WHERE user_id = ?`, userID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var pwEnc, notesEnc string
		if err := rows.Scan(&pwEnc, &notesEnc); err != nil {
			return false, err
		}
		if pwEnc != "" {
			if _, err := crypto.AESDecryptString(s.EncKey, pwEnc); err == nil {
				return true, nil
			}
		}
		if notesEnc != "" {
			if _, err := crypto.AESDecryptString(s.EncKey, notesEnc); err == nil {
				return true, nil
			}
		}
	}
	return false, rows.Err()
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
		setupIP:       ratelimit.New(setupIPPerMinute, time.Minute),
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
			for _, l := range s.limiters() {
				l.Cleanup()
			}
		}
	}()
	return s
}

// limiters 返回所有需要周期性 Cleanup 的限流器（单一来源）。
//
// 新增限流字段时**必须**同步加入此处，否则该限流器的键表会随攻击者可控的键
// （来源 IP / 邮箱 / 账号）无限增长（R10-01：`setupIP` 曾因此遗漏）。
// 这一不变量由 `TestAllLimitersAreCleaned` 用反射守住：任何实现了 `Cleanup()`
// 的 Server 字段都必须出现在本列表中。
func (s *Server) limiters() []interface{ Cleanup() } {
	return []interface{ Cleanup() }{
		s.loginIP,
		s.loginLock,
		s.registerIP,
		s.setupIP,
		s.resetIP,
		s.resetEmail,
		s.sendCodeIP,
		s.sendCodeEmail,
	}
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
		api.POST("/setup", s.ipLimit(s.setupIP, "请求过于频繁，请稍后再试"), s.handleSetup)
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
			// 头像属用户 PII：要求登录后访问（Web 端 <img> 同源请求自动带 Cookie；
			// 桌面端由 Rust 侧带 JWT 代理拉取），防止未认证者按自增 id 枚举全量头像。
			authed.GET("/avatar/:id", s.handleGetAvatar)
			// 密码条目统一走端到端加密的 Vault 协议（整库上传/下载），不存在明文接口。
			authed.GET("/vault", s.handleGetVault)
			authed.PUT("/vault", s.handlePutVault)
			authed.PUT("/vault-key", s.handlePutVaultKey)
			// 旧数据迁移专用：返回历史上由服务端静态密钥加密的明文，迁移完成后不再返回数据。
			authed.GET("/vault/legacy", s.handleGetLegacy)
			// 迁移完成上报：前端迁移成功后落标记，服务端据此永久关闭 legacy 明文接口。
			authed.POST("/vault/legacy/done", s.handleLegacyMigrationDone)
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
			// 自助改绑邮箱：向新邮箱发送所有权验证码（R7-01）。
			// 除「按收件地址 3 次/15 分」（sendCodeEmail）外，必须再叠加「按来源 IP」
			// 维度（sendCodeIP，与 /register/send-code、/reset/send-code 同桶）：
			// 否则登录用户可轮换收件地址无限发信，把服务器当邮件轰炸器（R13-01）。
			authed.POST("/me/email-code", s.ipLimit(s.sendCodeIP, "验证码发送过于频繁，请稍后再试"), s.handleSendMyEmailCode)

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
				// 过渡期提示：仍存在服务端可解密历史条目（未迁移）的账号清单。
				admin.GET("/legacy-pending", s.handleListLegacyPending)
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
// CSP 复用 shared/web.ContentSecurityPolicy（同样不含 frame-ancestors）。
func securityHeadersMiddleware(cfg config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("Referrer-Policy", "no-referrer")
		c.Header("Content-Security-Policy", web.ContentSecurityPolicy)
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

// gatewayIdentity 返回飞牛统一网关标识的当前访问者身份，用于把密匣会话与飞牛账号绑定。
// 网关在转发前完成登录态校验，并注入 X-Trim-Userid（UID）与 X-Trim-Username；
// 这里以 UID 优先、用户名兜底，并加前缀避免二者取值恰好相同时产生歧义。
// 直连端口等非网关场景不带这些头，返回空串表示「不参与账号隔离校验」。
func gatewayIdentity(c *gin.Context) string {
	if uid := strings.TrimSpace(c.GetHeader("X-Trim-Userid")); uid != "" {
		return "uid:" + uid
	}
	if name := strings.TrimSpace(c.GetHeader("X-Trim-Username")); name != "" {
		return "name:" + name
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

// secureRequest 判断当前请求是否应把会话 Cookie 标记为 Secure。
//
// 直连端口且为真 TLS 时恒为真。经反向代理 / 飞牛统一网关时，服务端收到的连接是
// 明文（网关经 unix socket 明文转发），`c.Request.TLS` 恒为 nil——此时唯一的
// "客户端是否处于 HTTPS" 依据是转发协议头 X-Forwarded-Proto。
//
// 安全约束：转发头只有在**采信代理头**时才允许影响判定（log.ProxyTrusted，与
// clientIP 同一决策），否则直连客户端可伪造 `X-Forwarded-Proto: https` 骗服务端
// 下发 Secure Cookie（在不支持 Secure 的场景下会导致 Cookie 被浏览器丢弃）。
func secureRequest(c *gin.Context) bool {
	if c.Request.TLS != nil {
		return true
	}
	if !log.ProxyTrusted(c.Request) {
		return false
	}
	proto := strings.TrimSpace(strings.ToLower(c.GetHeader("X-Forwarded-Proto")))
	if i := strings.Index(proto, ","); i >= 0 {
		proto = strings.TrimSpace(proto[:i])
	}
	return proto == "https"
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
		Secure:   secureRequest(c),
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
		Secure:   secureRequest(c),
		MaxAge:   -1,
	})
}

func (s *Server) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 仅认自定义账号密码签发的 JWT（不使用飞牛网关 X-Trim 头做身份认证），
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
					// 飞牛账号隔离：经统一网关访问时，会话必须与签发它的飞牛账号一致。
					// 切换飞牛账号后，浏览器里残留的 Cookie/sessionStorage 仍带着上一个
					// 飞牛账号签发的令牌，此处按 FnUID 不一致直接拒绝并清除 Cookie，
					// 使各飞牛账号之间互不沿用登录态（直连端口场景无该头，不参与校验）。
					if g := gatewayIdentity(c); g != "" && claims.FnUID != g {
						clearSessionCookie(c)
						c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized", "reason": "fnos_account_changed"})
						c.Abort()
						return
					}
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
	token, _ := auth.GenerateToken(s.Cfg.JWTSecret, id, req.Username, "superadmin", db.TokenVersion(s.DB, id), gatewayIdentity(c))
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
	// 邮箱唯一性（R7-01）：该邮箱已被占用则拒绝注册。
	// 此处调用方已通过邮箱验证码证明了对该邮箱的控制权，故直接提示不构成邮箱枚举泄露。
	var emailUsed int
	if err := s.DB.QueryRow(`SELECT COUNT(1) FROM users WHERE email = ?`, req.Email).Scan(&emailUsed); err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	if emailUsed > 0 {
		writeJSON(c, http.StatusConflict, gin.H{"error": "该邮箱已被注册，请直接登录或使用找回密码"})
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "hash error"})
		return
	}
	id, err := db.CreateUserWithNextID(s.DB, req.Username, hash, "user", req.Email, strings.TrimSpace(req.KdfSalt), req.VaultKeyEnc)
	if err != nil {
		// 注册场景的用户名冲突同样属业务错误：返回 409 而非 500。
		if errors.Is(err, db.ErrUsernameTaken) {
			writeJSON(c, http.StatusConflict, gin.H{"error": "用户名已存在"})
			return
		}
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	token, _ := auth.GenerateToken(s.Cfg.JWTSecret, id, req.Username, "user", db.TokenVersion(s.DB, id), gatewayIdentity(c))
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
	// 失败锁定键：**来源 IP + 账号** 联合维度。
	//
	// 早期实现只用账号名作键，导致「账号锁定 DoS」（R6-01）：任何人只要知道
	// 受害者用户名，用 5 次错误密码即可把该账号全局锁定 15 分钟，且到期后可
	// 立即续锁——受害者本人（密码正确、来自完全不同 IP）同样被拒。
	//
	// 加入来源维度后：
	//   - 同一来源对同一账号连续失败仍会被锁定（防暴力破解能力不变）；
	//   - 攻击者只能锁住「自己那一个来源」，不影响受害者从其他来源正常登录。
	// 跨来源的分布式暴力破解另有 `loginIP` 全局限流兜底（见路由上的 ipLimit）。
	lockKey := loginLockKey(clientIP(c), login)
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
	// R7-01：登录标识消歧。原实现 `WHERE username = ? OR email = ?` 在(username/email)
	// 命中多行时，QueryRow 只取第一行且无序，可能登错账号或使受害者被拒。
	// 改为"用户名精确匹配优先，未命中再按邮箱匹配"；邮箱已由唯一索引保证唯一。
	err := s.DB.QueryRow(`SELECT id, username, password_hash, role, status, COALESCE(vault_key_enc, ''), COALESCE(kdf_salt, '') FROM users WHERE username = ?`, login).Scan(&id, &uname, &hash, &role, &status, &vaultKeyEnc, &kdfSalt)
	if err == sql.ErrNoRows {
		err = s.DB.QueryRow(`SELECT id, username, password_hash, role, status, COALESCE(vault_key_enc, ''), COALESCE(kdf_salt, '') FROM users WHERE email = ?`, login).Scan(&id, &uname, &hash, &role, &status, &vaultKeyEnc, &kdfSalt)
	}
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
		// R8-06：不对外回显"账号已被停用"，避免一次性泄露"账号存在 + 口令正确 + 状态"。
		// 对外与失败路径保持一致的通用文案，差异仅进审计日志供管理员排查。
		log.LogAction(s.DB, id, uname, "login_disabled", "停用账号尝试登录", clientIP(c))
		writeJSON(c, http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
		return
	}
	s.loginLock.Reset(lockKey)
	log.LogAction(s.DB, id, uname, "login", "用户登录", clientIP(c))
	token, _ := auth.GenerateToken(s.Cfg.JWTSecret, id, uname, role, db.TokenVersion(s.DB, id), gatewayIdentity(c))
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
	// "放弃旧密码库"在语义上必须彻底：同时落标记封死本账号的 legacy 明文接口，
	// 否则只要 entries 表还残留任何可解密文，GET /vault/legacy 仍会吐明文。
	// 标记按 user_id 隔离，只影响当前用户，不会波及其他账号的迁移。
	if err := db.SetMeta(s.DB, legacyMigrationKey(claims.UserID), "1"); err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	log.LogAction(s.DB, claims.UserID, claims.Username, "reset_vault", "清空密码库并重置 vault key", clientIP(c))
	writeJSON(c, http.StatusOK, gin.H{"status": "ok"})
}

// handleLegacyMigrationDone 由前端在旧数据迁移成功后调用，落"迁移已完成"标记。
// 此后该账号的 GET /vault/legacy 返回 410，明文接口彻底关闭（一次性后门）。
//
// 标记**按账号隔离**：一个用户完成迁移不能影响其他用户的迁移能力。
func (s *Server) handleLegacyMigrationDone(c *gin.Context) {
	claims := currentClaims(c)
	if err := s.markLegacyMigrationDone(claims.UserID, claims.Username, clientIP(c)); err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	writeJSON(c, http.StatusOK, gin.H{"status": "ok"})
}

// handlePutVaultKey 更新「用主密钥包裹后的密码库密钥」。
//
// 口令再验证规则（R13-02）：账号**尚无** vault_key_enc（首次启用端到端加密）时允许
// 直接写入——此时没有既有解锁材料可被破坏；一旦已有 vault_key_enc，改写就是解锁材料
// 变更，必须携带正确的当前口令。否则持有泄露令牌者可把密文覆盖为任意值：正确口令
// 解不开、「旧密码恢复」也解不开（旧主密钥同样解不开垃圾密文），密码库永久无法解锁，
// 只剩「清空重建」一条路（不可逆数据丢失）。
func (s *Server) handlePutVaultKey(c *gin.Context) {
	claims := currentClaims(c)
	var req struct {
		VaultKeyEnc     string `json:"vault_key_enc"`
		CurrentPassword string `json:"current_password"`
	}
	if err := readJSON(c, &req); err != nil {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	if req.VaultKeyEnc == "" {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "vault_key_enc 不能为空"})
		return
	}
	var currentEnc, currentHash string
	if err := s.DB.QueryRow(`SELECT COALESCE(vault_key_enc, ''), password_hash FROM users WHERE id = ?`, claims.UserID).Scan(&currentEnc, &currentHash); err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	if strings.TrimSpace(currentEnc) != "" && !auth.CheckPassword(currentHash, req.CurrentPassword) {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "重新包裹密码库密钥需要当前密码"})
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
// 时间基准统一用 UTC：条目的 updated_at 由各端写入，RFC3339 带时区偏移在字符串比较
// 下不可比（"+08:00" 与 "Z" 混排会给出错误结论）；两端统一 UTC 后字符串比较才有意义。
// 注：真正可靠的冲突裁决已改用 revision 列，此处仅用于回收站过期判断。
func (s *Server) purgeExpiredTrash(userID int64) {
	threshold := time.Now().UTC().AddDate(0, 0, -recycleDays(s.DB)).Format(time.RFC3339)
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
//
// 安全约束（PT：明文后门）：本接口会遍历全表并尝试用服务端静态密钥解密，任何一条
// 恰好可解的记录都会以**明文**返回。它绝不能长期开放，因此：
//   - 迁移一旦完成，前端调用 POST /api/vault/legacy/done 落**该账号的**迁移标记；
//   - 标记存在时本接口直接返回 410 Gone，不再做任何遍历/解密；
//   - 放弃旧密码库（DELETE /vault）同样落标记——语义上"放弃旧数据"必须同时封死 legacy；
//   - 标记按 user_id 隔离：任一用户完成迁移**不会**影响其他账号的迁移能力。
//
// 生命期：本接口计划在 legacyAPIRemoveVersion（0.3.0）移除。管理员可经
// GET /api/legacy-pending 查询"仍存在服务端可解密历史条目"的账号并督促其迁移。
func (s *Server) handleGetLegacy(c *gin.Context) {
	claims := currentClaims(c)
	list := []db.Entry{}
	if s.legacyMigrationDone(claims.UserID) {
		writeJSON(c, http.StatusGone, gin.H{"error": "legacy migration already done"})
		return
	}
	if len(s.EncKey) == 0 {
		writeJSON(c, http.StatusOK, gin.H{"entries": list})
		return
	}
	rows, err := s.DB.Query(`SELECT id, uuid, sort_order, title, username, url, category, password_enc, notes_enc, created_at, updated_at, deleted, pinned, revision FROM entries WHERE user_id = ? ORDER BY sort_order ASC, id ASC`, claims.UserID)
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
		if err := rows.Scan(&e.ID, &e.UUID, &e.SortOrder, &e.Title, &e.Username, &e.URL, &e.Category, &pwEnc, &notesEnc, &e.CreatedAt, &e.UpdatedAt, &deleted, &pinned, &e.Revision); err != nil {
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

// handleListLegacyPending 列出「仍可能存在服务端可解密历史条目」的账号，供管理员督促迁移。
//
// 判定：未落 legacy 迁移标记，且该账号 entries 表中存在至少一条可用服务端静态密钥
// 解密的记录。这类账号的历史条目仍以端到端加密前的格式（服务端可解密）存在，
// 是过渡期的残余暴露面；legacyAPIRemoveVersion 之后接口关闭，未迁移数据需重新录入。
func (s *Server) handleListLegacyPending(c *gin.Context) {
	type pending struct {
		ID       int64  `json:"id"`
		Username string `json:"username"`
		Email    string `json:"email"`
	}
	list := []pending{}
	// 无服务端静态密钥时不存在"服务端可解密"的条目，直接返回空。
	if len(s.EncKey) != 0 {
		rows, err := s.DB.Query(`SELECT id, username, COALESCE(email, '') FROM users ORDER BY id`)
		if err != nil {
			writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
		type urow struct {
			id    int64
			name  string
			email string
		}
		var users []urow
		for rows.Next() {
			var u urow
			if err := rows.Scan(&u.id, &u.name, &u.email); err != nil {
				rows.Close()
				writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
				return
			}
			users = append(users, u)
		}
		rows.Close()
		for _, u := range users {
			if s.legacyMigrationDone(u.id) {
				continue
			}
			has, err := s.userHasLegacyPlaintext(u.id)
			if err != nil {
				writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
				return
			}
			if has {
				list = append(list, pending{ID: u.id, Username: u.name, Email: u.email})
			}
		}
	}
	writeJSON(c, http.StatusOK, gin.H{
		"count":          len(list),
		"users":          list,
		"remove_version": legacyAPIRemoveVersion,
	})
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

// reservedUsernames 是系统保留用户名集合，普通用户/管理员不得占用。
//
// 保留原因：历史兼容迁移 SeedAdmin 与用户名 "admin" 相关联。虽然该迁移已改为
// 一次性、带版本守卫（见 db.SeedAdmin），仍禁止新增/改名出保留名，作为纵深防御，
// 避免任何"用户名即角色"的隐式耦合再次成为提权面。
var reservedUsernames = map[string]bool{
	"admin":      true,
	"root":       true,
	"superadmin": true,
	"system":     true,
}

// isReservedUsername 判断用户名是否为系统保留名（大小写不敏感）。
func isReservedUsername(name string) bool {
	return reservedUsernames[strings.ToLower(strings.TrimSpace(name))]
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
	if isReservedUsername(req.Username) {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "该用户名为系统保留名，不可使用"})
		return
	}
	if req.Email == "" {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "邮箱不能为空"})
		return
	}
	if req.Role != "admin" && req.Role != "user" {
		req.Role = "user"
	}
	// 等级隔离（R9-01）：创建管理员账号属特权操作，仅 superadmin 可执行。
	// 否则普通 admin 虽不能管理同级 admin（R8-01），仍可"造一个管理员出来"，
	// 形成绕开同级隔离的提权路径。
	if req.Role == "admin" && currentClaims(c).Role != "superadmin" {
		writeJSON(c, http.StatusForbidden, gin.H{"error": "仅超级管理员可创建管理员账号"})
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
	// 邮箱唯一性（R7-01）：管理员添加用户时的邮箱也不得与他人重复。
	if req.Email != "" {
		var emailUsed int
		if err := s.DB.QueryRow(`SELECT COUNT(1) FROM users WHERE email = ?`, req.Email).Scan(&emailUsed); err != nil {
			writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
		if emailUsed > 0 {
			writeJSON(c, http.StatusConflict, gin.H{"error": "该邮箱已被其他账号使用"})
			return
		}
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "hash error"})
		return
	}
	if _, err := db.CreateUserWithNextID(s.DB, req.Username, hash, req.Role, req.Email, "", ""); err != nil {
		// 并发下两个同名请求可能都通过前置查重：此时应返回 409（业务冲突），
		// 而非 500（伪装成重试耗尽）。
		if errors.Is(err, db.ErrUsernameTaken) {
			writeJSON(c, http.StatusConflict, gin.H{"error": "用户名已存在"})
			return
		}
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
		// 保留用户名（R11-03）：批量导入是第 4 条建号路径，必须与 handleCreateUser /
		// handleUpdateUser / handleUpdateMe 同口径拒绝 admin/root/superadmin/system。
		// 否则可导入与超管同名的普通账号，突破"用户名≠角色"的纵深防御约定。
		if isReservedUsername(username) {
			skipped++
			continue
		}
		role := "user"
		rl := strings.TrimSpace(u.Role)
		if rl == "admin" || rl == "管理员" || rl == "管理員" {
			role = "admin"
		}
		// 等级隔离（R9-01）：非 superadmin 不得借批量导入创建管理员账号——
		// 该行按"无法创建"处理（计入 skipped），避免绕过 handleCreateUser 的限制。
		if role == "admin" && claims.Role != "superadmin" {
			skipped++
			continue
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
		// 邮箱唯一性（R7-01）：邮箱已被占用（含本批先前导入的行）则该行跳过。
		if em := strings.TrimSpace(u.Email); em != "" {
			var emailUsed int
			if err := s.DB.QueryRow(`SELECT COUNT(1) FROM users WHERE email = ?`, em).Scan(&emailUsed); err != nil {
				writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
				return
			}
			if emailUsed > 0 {
				skipped++
				continue
			}
		}
		hash, err := auth.HashPassword(password)
		if err != nil {
			writeJSON(c, http.StatusInternalServerError, gin.H{"error": "hash error"})
			return
		}
		if _, err := db.CreateUserWithNextID(s.DB, username, hash, role, strings.TrimSpace(u.Email), "", ""); err != nil {
			// 批量导入时并发同名属"该行跳过"，不应中断整批导入。
			if errors.Is(err, db.ErrUsernameTaken) {
				skipped++
				continue
			}
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
	// 头像文件随账号一并删除：id 会被后续注册复用，残留头像会被新用户继承展示。
	removeAvatarFiles(id)
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
	} else if username != target.Username && isReservedUsername(username) {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "该用户名为系统保留名，不可使用"})
		return
	}
	role := target.Role
	if req.Role != "" {
		if req.Role != "admin" && req.Role != "user" {
			writeJSON(c, http.StatusBadRequest, gin.H{"error": "role 只能为 admin 或 user"})
			return
		}
		role = req.Role
	}
	// 等级隔离（R9-01）：把普通用户提升为管理员是特权操作，仅 superadmin 可执行；
	// 否则 admin 可"造/升"出一个不受同级隔离约束的中间人（R8-01 的旁路）。
	if role == "admin" && target.Role != "admin" && claims.Role != "superadmin" {
		writeJSON(c, http.StatusForbidden, gin.H{"error": "仅超级管理员可授予管理员角色"})
		return
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
	// 邮箱唯一性（R7-01）：管理员改他人邮箱无需所有权验证码（管理员可管理该用户），
	// 但必须避免与他人的邮箱重复。
	if email != target.Email {
		var emailUsed int
		if err := s.DB.QueryRow(`SELECT COUNT(1) FROM users WHERE email = ? AND id != ?`, email, id).Scan(&emailUsed); err != nil {
			writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
		if emailUsed > 0 {
			writeJSON(c, http.StatusConflict, gin.H{"error": "该邮箱已被其他账号使用"})
			return
		}
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

// handleSendMyEmailCode 向「新邮箱」发送自助改绑验证码（R7-01）。
// 仅登录用户可用，供 handleUpdateMe 改邮箱时的所有权验证；管理员改他人邮箱不经过此接口。
func (s *Server) handleSendMyEmailCode(c *gin.Context) {
	claims := currentClaims(c)
	var req struct {
		Email string `json:"email"`
	}
	if err := readJSON(c, &req); err != nil {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" || !strings.Contains(req.Email, "@") {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "邮箱格式不正确"})
		return
	}
	if !auth.SMTPEnabled(s.DB) || !auth.SMTPConfigured(s.DB) {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "未配置邮件服务，无法发送验证码"})
		return
	}
	// 已被其他账号占用的邮箱直接拒绝：省去一次发信，也避免骚扰该邮箱的主人。
	var used int
	if err := s.DB.QueryRow(`SELECT COUNT(1) FROM users WHERE email = ? AND id != ?`, req.Email, claims.UserID).Scan(&used); err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	if used > 0 {
		writeJSON(c, http.StatusConflict, gin.H{"error": "该邮箱已被其他账号使用"})
		return
	}
	// 邮箱维度限流：防止登录用户把本接口当作发信轰炸器。
	if !s.sendCodeEmail.Allow(strings.ToLower(req.Email)) {
		writeJSON(c, http.StatusTooManyRequests, gin.H{"error": "验证码发送过于频繁，请稍后再试"})
		return
	}
	if err := auth.SendVerifyCode(s.DB, s.EncKey, req.Email, "bind_email"); err != nil {
		// 原始 SMTP 错误仅进审计日志（管理员可见），对外返回通用文案。
		log.LogAction(s.DB, claims.UserID, claims.Username, "send_bind_email_code_failed", "发送改绑邮箱验证码失败: "+err.Error(), clientIP(c))
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "验证码发送失败，请稍后重试"})
		return
	}
	writeJSON(c, http.StatusOK, gin.H{"status": "ok"})
}

// handleUpdateMe 用户修改自己的用户名、邮箱与密码。
func (s *Server) handleUpdateMe(c *gin.Context) {
	claims := currentClaims(c)
	var req struct {
		Username        string `json:"username"`
		Email           string `json:"email"`
		EmailCode       string `json:"email_code"`
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
		KdfSalt         string `json:"kdf_salt"`
		VaultKeyEnc     string `json:"vault_key_enc"`
	}
	if err := readJSON(c, &req); err != nil {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	username := strings.TrimSpace(req.Username)
	if username == "" {
		username = claims.Username
	}
	if username != claims.Username {
		// 保留名校验：与 handleCreateUser / handleUpdateUser / handleImportUsers 保持一致，
		// 避免用户经自助改名绕过"用户名即角色"的纵深防御。
		if isReservedUsername(username) {
			writeJSON(c, http.StatusBadRequest, gin.H{"error": "该用户名为系统保留名，不可使用"})
			return
		}
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
	// 账号身份凭证变更再验证（修复账号接管链）：用户名/邮箱与口令同属账号身份，
	// 任何一项实际变更都要求当前密码。否则持有泄露令牌的攻击者可先改绑自己的
	// 邮箱，再经「邮箱重置口令」闭环完成持久接管——改密会验证旧口令，唯独改
	// 邮箱/用户名不验，防护不对称。
	var currentHash, currentEmail string
	if err := s.DB.QueryRow(`SELECT password_hash, COALESCE(email, '') FROM users WHERE id = ?`, claims.UserID).Scan(&currentHash, &currentEmail); err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	usernameChanged := username != claims.Username
	// 邮箱留空表示"不修改"：仅当提交了非空且与当前值不同的邮箱时才算变更，
	// 避免改密/改名请求未携带 email 时把邮箱误清空。
	emailChanged := req.Email != "" && req.Email != currentEmail
	effectiveEmail := currentEmail
	if req.Email != "" {
		effectiveEmail = req.Email
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
	}
	// 解锁材料（派生盐 kdf_salt / 包裹后的密码库密钥 vault_key_enc）与口令、用户名、
	// 邮箱同属账号身份，任何实际改写都必须做当前口令再验证（R13-02）：否则持有泄露
	// 令牌的攻击者可把 kdf_salt 改成任意值，使正确口令再也派生不出能解开
	// vault_key_enc 的主密钥 —— 密码库永久无法解锁，且「旧密码恢复」同样救不回
	// （旧主密钥解不开被改写后的密文），只能清空重建。
	newSalt := strings.TrimSpace(req.KdfSalt)
	newVaultKey := strings.TrimSpace(req.VaultKeyEnc)
	if req.NewPassword != "" || usernameChanged || emailChanged || newSalt != "" || newVaultKey != "" {
		if !auth.CheckPassword(currentHash, req.CurrentPassword) {
			writeJSON(c, http.StatusBadRequest, gin.H{"error": "当前密码错误"})
			return
		}
	}

	// 邮箱改绑的所有权验证（R7-01）：自助改邮箱必须提供发送到**新邮箱**的验证码，
	// 防止用户把账号邮箱指向他人地址（进而引发登录歧义与重置串扰）。
	// 管理员经用户管理改邮箱不走此校验（见 handleUpdateUser）。
	if emailChanged {
		if req.Email == "" || !strings.Contains(req.Email, "@") {
			writeJSON(c, http.StatusBadRequest, gin.H{"error": "邮箱格式不正确"})
			return
		}
		if !auth.CheckVerification(s.DB, req.Email, req.EmailCode, "bind_email") {
			writeJSON(c, http.StatusBadRequest, gin.H{"error": "新邮箱验证码错误或已过期"})
			return
		}
		var used int
		if err := s.DB.QueryRow(`SELECT COUNT(1) FROM users WHERE email = ? AND id != ?`, req.Email, claims.UserID).Scan(&used); err != nil {
			writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
		if used > 0 {
			writeJSON(c, http.StatusConflict, gin.H{"error": "该邮箱已被其他账号使用"})
			return
		}
	}

	// 一致性保护：密码或派生盐变更会改变主密钥，若账号已存在 vault_key_enc，
	// 必须同时提交用新主密钥重新加密的 vault_key_enc —— 否则旧密文将永久无法解密。
	// 客户端未解锁密码库时应拒绝改密（无法重新包裹密钥）。
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
		if _, err := tx.Exec(`UPDATE users SET username=?, email=?, password_hash=?, token_version = COALESCE(token_version, 0) + 1 WHERE id=?`, username, effectiveEmail, newHash, claims.UserID); err != nil {
			writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
	} else {
		if _, err := tx.Exec(`UPDATE users SET username=?, email=? WHERE id=?`, username, effectiveEmail, claims.UserID); err != nil {
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
		if tok, err := auth.GenerateToken(s.Cfg.JWTSecret, claims.UserID, username, claims.Role, db.TokenVersion(s.DB, claims.UserID), gatewayIdentity(c)); err == nil {
			setSessionCookie(c, tok)
			resp["token"] = tok
		}
	}
	writeJSON(c, http.StatusOK, resp)
}

// ---- 数据访问辅助 ----

// listEntriesAll 返回该用户的全部条目（含墓碑），用于同步 vault 上传/下载。
func (s *Server) listEntriesAll(userID int64) ([]db.Entry, error) {
	rows, err := s.DB.Query(`SELECT id, uuid, sort_order, title, username, url, category, password_enc, notes_enc, created_at, updated_at, deleted, pinned, revision FROM entries WHERE user_id = ? ORDER BY pinned DESC, sort_order ASC, id ASC`, userID)
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
		if err := rows.Scan(&e.ID, &e.UUID, &e.SortOrder, &e.Title, &e.Username, &e.URL, &e.Category, &pwEnc, &notesEnc, &e.CreatedAt, &e.UpdatedAt, &deleted, &pinned, &e.Revision); err != nil {
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
	// 同时读取服务端当前 revision，用于本次写入时单调递增（见下方 revision 计算）。
	storedRev := make(map[string]int64)
	rows, err := s.DB.Query(`SELECT uuid, id, pinned, revision FROM entries WHERE user_id = ?`, userID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var u string
		var id, p int
		var rev int64
		if err := rows.Scan(&u, &id, &p, &rev); err != nil {
			// 不静默忽略：Scan 失败会让 storedRev 缺项，导致本次写入的 revision 被
			// 退化为 1（版本号异常）。此处直接中止，避免把损坏的状态写回去。
			rows.Close()
			return err
		}
		if p == 1 {
			if u != "" {
				storedPins["u:"+u] = true
			}
			storedPins["i:"+strconv.Itoa(id)] = true
		}
		if u != "" {
			storedRev["u:"+u] = rev
		}
		storedRev["i:"+strconv.Itoa(id)] = rev
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
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
		// revision：服务端每次写入整库时单调 +1。
		//
		// 安全要点（PT：客户端可控 revision）：**绝不能把客户端传入的 revision 当作
		// 基线参与 max 计算**。整库上传下每条条目每次都会被重写，若采纳客户端数值，
		// 任何持有旧副本的一方只要把 revision 填成极大值（如 1e9），就能：
		//   ① 让陈旧数据在下次合并时"看起来更新"从而覆盖服务端新数据（丢写）；
		//   ② 把该条目的 revision 永久抬高，使其他设备的真实修改全部被判为"旧"而丢弃。
		// 因此 revision 严格由服务端既有值推导，客户端数值一律忽略。
		revKey := "u:" + e.UUID
		if e.UUID == "" {
			revKey = "i:" + strconv.FormatInt(e.ID, 10)
		}
		revision := storedRev[revKey] + 1
		_, err = tx.Exec(`INSERT INTO entries (id, uuid, sort_order, user_id, title, username, url, category, password_enc, notes_enc, created_at, updated_at, deleted, pinned, revision) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			e.ID, e.UUID, e.SortOrder, userID, e.Title, e.Username, e.URL, e.Category, pwEnc, notesEnc, e.CreatedAt, e.UpdatedAt, deleted, pinned, revision)
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
		// 原始 SMTP 错误仅记入审计日志（管理员可见，用于排查发信配置）；
		// 对外返回通用文案，避免向未认证请求者泄露内部 SMTP 主机/端口/连通性。
		log.LogAction(s.DB, 0, req.Email, "send_register_code_failed", "发送注册验证码失败: "+err.Error(), clientIP(c))
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "验证码发送失败，请稍后重试"})
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
	// 先解析唯一目标账号，再按 id 定向更新（R7-01）：原 `UPDATE ... WHERE email = ?`
	// 在邮箱非唯一时会对多个账号批量改密（跨账号串扰）。邮箱现已唯一，按 id 更新更明确。
	var targetID int64
	if err := s.DB.QueryRow(`SELECT id FROM users WHERE email = ?`, req.Email).Scan(&targetID); err != nil {
		if err == sql.ErrNoRows {
			writeJSON(c, http.StatusNotFound, gin.H{"error": "该邮箱未注册"})
			return
		}
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	// 邮件重置口令同样递增令牌版本：重置前泄露的令牌立即失效（PT-06）。
	if _, err := s.DB.Exec(`UPDATE users SET password_hash = ?, token_version = COALESCE(token_version, 0) + 1 WHERE id = ?`, hash, targetID); err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
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
	smtp := auth.LoadSMTPConfig(s.DB, s.EncKey)
	// SMTP 口令不以明文回传（R6-02）：管理员会话被接管时，明文口令会被直接读走，
	// 而该口令常与主邮箱同口令，危害外溢。与导出接口（handleExportSettings）对齐，
	// 已配置时返回掩码 auth.MaskedSecret；未配置时保持空串（前端占位提示依赖空值）。
	// 掩码值在 handleUpdateSettings 中被识别为"保持原值"，故前端"原样回传"不会破坏口令。
	if smtp.Password != "" {
		smtp.Password = auth.MaskedSecret
	}
	writeJSON(c, http.StatusOK, gin.H{
		"smtp":                     smtp,
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
	// 逐项写入并收集失败：任何一项落库失败都不能再回 {"status":"ok"}，
	// 否则管理员会看到"保存成功"但 SMTP/注册开关等静默未生效（磁盘满、库只读、并发写锁）。
	var failed []string
	set := func(key, value string) {
		if err := db.SetMeta(s.DB, key, value); err != nil {
			failed = append(failed, key)
		}
	}
	if req.Mode != "" {
		if req.Mode != "code" && req.Mode != "link" && req.Mode != "none" {
			writeJSON(c, http.StatusBadRequest, gin.H{"error": "mode 必须为 code/link/none"})
			return
		}
		set("email_verify_mode", req.Mode)
	}
	allowedVendor := map[string]bool{
		"qq": true, "126": true, "163": true, "gmail": true, "outlook": true, "custom": true,
	}
	if req.Vendor != "" {
		if !allowedVendor[req.Vendor] {
			writeJSON(c, http.StatusBadRequest, gin.H{"error": "vendor 非法"})
			return
		}
		set("smtp_vendor", req.Vendor)
	}
	set("smtp_host", req.Host)
	// 端口与数值型设置做范围钳制：管理员（或托管了管理员会话的攻击者）写入
	// 负数/超大值会导致 SMTP 不可用、口令策略无法满足、回收站永不清理。
	set("smtp_port", strconv.Itoa(clampRange(req.Port, 1, 65535, 465)))
	set("smtp_username", req.Username)
	set("smtp_from", req.From)
	// SMTP 口令加密后落库（PT-07）；掩码值表示"保持原口令不变"。
	if req.Password != "" && req.Password != auth.MaskedSecret {
		enc, err := auth.EncryptSMTPPassword(s.EncKey, req.Password)
		if err != nil {
			writeJSON(c, http.StatusInternalServerError, gin.H{"error": "保存 SMTP 口令失败"})
			return
		}
		set("smtp_password", enc)
	}
	if req.SSL {
		set("smtp_ssl", "true")
	} else {
		set("smtp_ssl", "false")
	}
	if req.SMTPEnabled != nil {
		if *req.SMTPEnabled {
			set("smtp_enabled", "true")
		} else {
			set("smtp_enabled", "false")
		}
	}
	if req.AllowRegistration != nil {
		if *req.AllowRegistration {
			set("allow_registration", "true")
		} else {
			set("allow_registration", "false")
		}
	}
	if req.PasswordMinLength > 0 {
		set("password_min_length", strconv.Itoa(clampRange(req.PasswordMinLength, 6, 128, 8)))
	}
	if req.PasswordRequireComplex != nil {
		if *req.PasswordRequireComplex {
			set("password_require_complex", "true")
		} else {
			set("password_require_complex", "false")
		}
	}
	if req.Recycle != nil {
		if *req.Recycle {
			set("recycle", "true")
		} else {
			set("recycle", "false")
		}
	}
	if req.RecycleDays > 0 {
		set("recycle_days", strconv.Itoa(clampRange(req.RecycleDays, 1, 3650, 30)))
	}
	if req.Site != nil {
		set("site_footer_text", req.Site.FooterText)
	}
	if len(failed) > 0 {
		writeJSON(c, http.StatusInternalServerError, gin.H{
			"error":  "部分设置保存失败",
			"failed": failed,
		})
		return
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
		// 原始 SMTP 错误仅进审计日志（管理员可见，便于排查配置），对外返回通用文案，
		// 避免泄露 SMTP 主机/端口/连通性等基础设施细节（R7-03）。与注册发码路径一致。
		claims := currentClaims(c)
		log.LogAction(s.DB, claims.UserID, claims.Username, "test_email_failed", "测试邮件发送失败: "+err.Error(), clientIP(c))
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "测试邮件发送失败，请检查 SMTP 配置或查看审计日志"})
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

// clampRange 把 value 钳制到 [lo, hi]；value <= 0（未提供/非法）时回退到 def。
func clampRange(value, lo, hi, def int) int {
	if value <= 0 {
		return def
	}
	if value < lo {
		return lo
	}
	if value > hi {
		return hi
	}
	return value
}

// clampPortMeta 把导入件里的 smtp_port 钳制到合法区间；非法（非数字）返回空串表示"跳过该项"。
// R8-04：更新路径（handleUpdateSettings）已对端口做 clampRange，导入路径此前遗漏——
// 导入 0/负数/超范围端口会让 SMTP 静默失效（界面仍显示"已启用"）。
func clampPortMeta(v string) string {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return ""
	}
	return strconv.Itoa(clampRange(n, 1, 65535, 465))
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
		// R8-04：端口同样要钳制，否则导入 0/负数/超范围值会让 SMTP 静默失效。
		if k == "smtp_port" {
			v = clampPortMeta(v)
			if v == "" {
				continue
			}
		}
		// PT-07：SMTP 口令必须加密后落库。导出文件里通常是掩码或明文，两条分支都不能
		// 直接 SetMeta —— 否则明文口令会写进 meta 表，破坏既定的密钥治理。
		if k == "smtp_password" {
			enc, err := auth.EncryptSMTPPassword(s.EncKey, v)
			if err != nil {
				writeJSON(c, http.StatusInternalServerError, gin.H{"error": "导入 SMTP 口令失败"})
				return
			}
			v = enc
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

// loginLockKey 组合「来源 IP + 账号」作为登录失败锁定的键。
//
// 为什么要带来源维度：若只用账号名，任何人用少量错误密码即可把目标账号
// 全局锁定（账号锁定 DoS，R6-01）——受害者从自己的 IP、用正确密码也被拒。
// 带上来源后，锁定只作用于发起失败尝试的那个来源，攻击者无法波及他人。
//
// 部署依赖：来源 IP 取自 log.ClientIP，它仅在 `TRUST_PROXY=true` 时采信
// X-Forwarded-For / X-Real-IP；否则用 TCP 对端地址。**若服务置于飞牛网关等
// 反向代理之后而又未开启 TRUST_PROXY，则所有请求的 IP 会退化为同一个
// （网关地址），本维度失效、退回到近似的账号全局锁定。** 网关部署务必
// 设置 TRUST_PROXY=true（且仅信任可信网关写入的转发头）。
//
// 注意：账号部分统一转小写（用户名不区分大小写）。
func loginLockKey(ip, login string) string {
	return strings.ToLower(strings.TrimSpace(ip)) + "|" + strings.ToLower(strings.TrimSpace(login))
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

// removeAvatarFiles 删除该用户的全部头像文件。
// 用户 id 会被回收复用（FindNextUserID），头像不随账号一并删除的话，
// 残留文件会被分配到同一 id 的新用户「继承」展示，构成跨用户信息残留。
func removeAvatarFiles(userID int64) {
	matches, _ := filepath.Glob(filepath.Join(avatarDir(), strconv.FormatInt(userID, 10)+".*"))
	for _, m := range matches {
		_ = os.Remove(m)
	}
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
