// Package handlers 提供 Gin HTTP 处理器、路由注册与中间件。
package handlers

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
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
)

// Server 持有共享运行时状态（配置、数据库、加密密钥）。
type Server struct {
	Cfg    config.Config
	DB     *sql.DB
	EncKey []byte
}

// NewServer 构造一个 Server 实例。
func NewServer(cfg config.Config, database *sql.DB, encKey []byte) *Server {
	return &Server{Cfg: cfg, DB: database, EncKey: encKey}
}

// RegisterRoutes 在 gin.Engine 上注册全部 API 路由与 CORS 中间件。
func RegisterRoutes(r *gin.Engine, cfg config.Config, database *sql.DB, encKey []byte) {
	s := NewServer(cfg, database, encKey)
	s.register(r)
}

func (s *Server) register(r *gin.Engine) {
	r.Use(s.corsMiddleware())

	api := r.Group("/api")
	{
		// 公开
		api.GET("/health", s.handleHealth)
		api.GET("/status", s.handleStatus)
		api.POST("/setup", s.handleSetup)
		api.GET("/avatar/:id", s.handleGetAvatar)
		api.POST("/register", s.handleRegister)
		api.POST("/register/send-code", s.handleSendRegisterCode)
		api.GET("/settings/public", s.handlePublicSettings)
		api.POST("/login", s.handleLogin)
		api.POST("/reset/send-code", s.handleSendResetCode)
		api.POST("/reset", s.handleResetPassword)

		// 登录用户
		authed := api.Group("", s.authMiddleware())
		{
			authed.GET("/me", s.handleMe)
			authed.PUT("/me", s.handleUpdateMe)
			authed.POST("/me/avatar", s.handleUploadAvatar)
			authed.GET("/entries", s.handleListEntries)
			authed.POST("/entries", s.handleCreateEntry)
			authed.POST("/entries/import", s.handleImportEntries)
			authed.POST("/entries/import-text", s.handleImportText)
			authed.PUT("/entries/:id", s.handleUpdateEntry)
			authed.DELETE("/entries/:id", s.handleDeleteEntry)
			authed.GET("/entries/trash", s.handleListTrash)
			authed.POST("/entries/trash/empty", s.handleEmptyTrash)
			authed.POST("/entries/:id/restore", s.handleRestoreEntry)
			authed.DELETE("/entries/:id/purge", s.handlePurgeEntry)
			authed.GET("/vault", s.handleGetVault)
			authed.PUT("/vault", s.handlePutVault)

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
			}
		}
	}
}

// ---- 中间件 ----

func (s *Server) corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

func (s *Server) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1. JWT 优先：用户在登录页主动登录（携带 Bearer token）时，身份以 token 为准。
		//    飞牛网关的 X-Trim 头表示飞牛系统当前登录用户，若优先于 JWT，会导致
		//    「登录 test 却变成 admin」；因此主动登录的 JWT 优先于网关 SSO。
		if h := c.GetHeader("Authorization"); strings.HasPrefix(h, "Bearer ") {
			if claims, err := auth.ParseToken(s.Cfg.JWTSecret, strings.TrimPrefix(h, "Bearer ")); err == nil {
				var role, status string
				if err := s.DB.QueryRow(`SELECT role, status FROM users WHERE id = ?`, claims.UserID).Scan(&role, &status); err == nil && status == "active" {
					claims.Role = role
					c.Set("claims", claims)
					c.Next()
					return
				}
			}
		}

		// 2. 网关身份：飞牛内嵌访问（无主动登录 token）时，使用飞牛网关转发的 X-Trim 鉴权头自动登录。
		if gwUser := strings.TrimSpace(c.GetHeader("X-Trim-Username")); gwUser != "" {
			var id int64
			var role, status string
			if err := s.DB.QueryRow(`SELECT id, role, status FROM users WHERE username = ?`, gwUser).Scan(&id, &role, &status); err == nil && status == "active" {
				// 网关用 X-Trim-Isadmin 标识当前 NAS 用户是否为管理员；内嵌访问时据此授予管理员权限。
				if role == "user" && strings.EqualFold(c.GetHeader("X-Trim-Isadmin"), "true") {
					role = "admin"
				}
				claims := &auth.Claims{UserID: id, Username: gwUser, Role: role}
				// 下发 HttpOnly Cookie：网关刷新时 X-Trim 可能缺失，靠 Cookie 维持登录态。
				if token, err := auth.GenerateToken(s.Cfg.JWTSecret, id, gwUser, role); err == nil {
					c.SetCookie("cryptbox_token", token, 7*24*3600, "/", "", false, true)
				}
				c.Set("claims", claims)
				c.Next()
				return
			}
		}

		// 3. Cookie 回退：网关刷新后 X-Trim 未转发时，用登录时下发的 Cookie。
		// 注意：保留 Cookie 中的角色（含网关鉴权时 X-Trim-Isadmin 的管理员提升），
		// 仅重新校验账号仍为 active，否则刷新后管理员权限会丢失。
		if cookieToken, err := c.Cookie("cryptbox_token"); err == nil && cookieToken != "" {
			if claims, err := auth.ParseToken(s.Cfg.JWTSecret, cookieToken); err == nil {
				var status string
				if err := s.DB.QueryRow(`SELECT status FROM users WHERE id = ?`, claims.UserID).Scan(&status); err == nil && status == "active" {
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
	writeJSON(c, http.StatusOK, gin.H{"initialized": db.IsInitialized(s.DB)})
}

// handleSetup 首次设置超级管理员账号（系统无用户时）。
func (s *Server) handleSetup(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := readJSON(c, &req); err != nil {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || len(req.Password) < 6 {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "用户名不能为空，密码至少 6 位"})
		return
	}
	if db.IsInitialized(s.DB) {
		writeJSON(c, http.StatusConflict, gin.H{"error": "系统已初始化"})
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
	id, err := db.SetupAdmin(s.DB, req.Username, hash)
	if err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	token, _ := auth.GenerateToken(s.Cfg.JWTSecret, id, req.Username, "superadmin")
	log.LogAction(s.DB, id, req.Username, "setup", "初始化超级管理员", clientIP(c))
	writeJSON(c, http.StatusOK, gin.H{"token": token, "username": req.Username, "role": "superadmin", "avatar": avatarName(id)})
}

func (s *Server) handleRegister(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Email    string `json:"email"`
		Code     string `json:"code"`
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
	_, err = s.DB.Exec(`INSERT INTO users (id, username, password_hash, role, status, email) VALUES (?, ?, ?, 'user', 'active', ?)`, id, req.Username, hash, req.Email)
	if err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	token, _ := auth.GenerateToken(s.Cfg.JWTSecret, id, req.Username, "user")
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
	var (
		id     int64
		uname  string
		hash   string
		role   string
		status string
	)
	err := s.DB.QueryRow(`SELECT id, username, password_hash, role, status FROM users WHERE username = ? OR email = ?`, login, login).Scan(&id, &uname, &hash, &role, &status)
	if err == sql.ErrNoRows || (err == nil && !auth.CheckPassword(hash, req.Password)) {
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
	log.LogAction(s.DB, id, uname, "login", "用户登录", clientIP(c))
	token, _ := auth.GenerateToken(s.Cfg.JWTSecret, id, uname, role)
	writeJSON(c, http.StatusOK, gin.H{"token": token, "username": uname, "role": role, "avatar": avatarName(id)})
}

func (s *Server) handleMe(c *gin.Context) {
	claims := currentClaims(c)
	var username, email string
	_ = s.DB.QueryRow(`SELECT username, email FROM users WHERE id = ?`, claims.UserID).Scan(&username, &email)
	writeJSON(c, http.StatusOK, gin.H{
		"id":       claims.UserID,
		"username": username,
		"email":    email,
		"avatar":   avatarName(claims.UserID),
		"role":     claims.Role,
	})
}

// ---- 密码条目 CRUD（仅本人） ----

func (s *Server) handleListEntries(c *gin.Context) {
	claims := currentClaims(c)
	list, err := s.listEntries(claims.UserID)
	if err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	writeJSON(c, http.StatusOK, gin.H{"entries": list})
}

func (s *Server) handleCreateEntry(c *gin.Context) {
	claims := currentClaims(c)
	var e db.Entry
	if err := readJSON(c, &e); err != nil {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	saved, err := s.saveEntry(claims.UserID, e)
	if err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	log.LogAction(s.DB, claims.UserID, claims.Username, "add_entry", "添加密码 "+saved.Title, clientIP(c))
	writeJSON(c, http.StatusOK, saved)
}

func (s *Server) handleUpdateEntry(c *gin.Context) {
	claims := currentClaims(c)
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var e db.Entry
	if err := readJSON(c, &e); err != nil {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	e.ID = id
	saved, err := s.saveEntry(claims.UserID, e)
	if err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	log.LogAction(s.DB, claims.UserID, claims.Username, "update_entry", "修改密码 "+saved.Title, clientIP(c))
	writeJSON(c, http.StatusOK, saved)
}

func (s *Server) handleDeleteEntry(c *gin.Context) {
	claims := currentClaims(c)
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var title string
	var sortOrder int64
	_ = s.DB.QueryRow(`SELECT title, sort_order FROM entries WHERE id = ? AND user_id = ?`, id, claims.UserID).Scan(&title, &sortOrder)
	if db.GetMeta(s.DB, "recycle") == "false" {
		// 不走回收站：物理删除
		_, err = s.DB.Exec(`DELETE FROM entries WHERE id = ? AND user_id = ?`, id, claims.UserID)
		if err != nil {
			writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
		s.renumberAfterDelete(claims.UserID, sortOrder)
	} else {
		// 走回收站：软删除，打墓碑标记并保留密文以便恢复。
		now := time.Now().Format(time.RFC3339)
		_, err = s.DB.Exec(`UPDATE entries SET deleted = 1, sort_order = 0, updated_at = ? WHERE id = ? AND user_id = ?`, now, id, claims.UserID)
		if err != nil {
			writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
		s.renumberAfterDelete(claims.UserID, sortOrder)
	}
	log.LogAction(s.DB, claims.UserID, claims.Username, "delete_entry", "删除密码 "+title, clientIP(c))
	writeJSON(c, http.StatusOK, gin.H{"status": "ok"})
}

// renumberAfterDelete 删除后重排：把序号大于被删序号、且未删除的条目前移一位，保持序号连续。
func (s *Server) renumberAfterDelete(userID int64, sortOrder int64) {
	if sortOrder <= 0 {
		return
	}
	_, _ = s.DB.Exec(`UPDATE entries SET sort_order = sort_order - 1 WHERE user_id = ? AND sort_order > ? AND deleted = 0`, userID, sortOrder)
}

// handleListTrash 返回当前用户回收站中的墓碑条目（含已解密内容），读取前先清理过期条目。
func (s *Server) handleListTrash(c *gin.Context) {
	claims := currentClaims(c)
	s.purgeExpiredTrash(claims.UserID)
	list, err := s.listTrash(claims.UserID)
	if err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	writeJSON(c, http.StatusOK, gin.H{"entries": list})
}

// handleRestoreEntry 恢复回收站中的条目。
func (s *Server) handleRestoreEntry(c *gin.Context) {
	claims := currentClaims(c)
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var maxSort int64
	_ = s.DB.QueryRow(`SELECT COALESCE(MAX(sort_order), 0) FROM entries WHERE user_id = ? AND deleted = 0`, claims.UserID).Scan(&maxSort)
	now := time.Now().Format(time.RFC3339)
	_, err = s.DB.Exec(`UPDATE entries SET deleted = 0, sort_order = ?, updated_at = ? WHERE id = ? AND user_id = ?`, maxSort+1, now, id, claims.UserID)
	if err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	log.LogAction(s.DB, claims.UserID, claims.Username, "restore_entry", "恢复密码 id="+strconv.FormatInt(id, 10), clientIP(c))
	writeJSON(c, http.StatusOK, gin.H{"status": "ok"})
}

// handlePurgeEntry 从回收站永久删除单条条目。
func (s *Server) handlePurgeEntry(c *gin.Context) {
	claims := currentClaims(c)
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	_, err = s.DB.Exec(`DELETE FROM entries WHERE id = ? AND user_id = ? AND deleted = 1`, id, claims.UserID)
	if err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	log.LogAction(s.DB, claims.UserID, claims.Username, "purge_entry", "永久删除密码 id="+strconv.FormatInt(id, 10), clientIP(c))
	writeJSON(c, http.StatusOK, gin.H{"status": "ok"})
}

// handleEmptyTrash 清空当前用户回收站。
func (s *Server) handleEmptyTrash(c *gin.Context) {
	claims := currentClaims(c)
	res, err := s.DB.Exec(`DELETE FROM entries WHERE user_id = ? AND deleted = 1`, claims.UserID)
	if err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	n, _ := res.RowsAffected()
	log.LogAction(s.DB, claims.UserID, claims.Username, "empty_trash", "清空回收站", clientIP(c))
	writeJSON(c, http.StatusOK, gin.H{"count": n})
}

// listTrash 返回该用户回收站中的墓碑条目（解密后的领域模型）。
func (s *Server) listTrash(userID int64) ([]db.Entry, error) {
	rows, err := s.DB.Query(`SELECT id, sort_order, title, username, url, category, password_enc, notes_enc, created_at, updated_at, deleted FROM entries WHERE user_id = ? AND deleted = 1 ORDER BY updated_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []db.Entry{}
	for rows.Next() {
		var e db.Entry
		var pwEnc, notesEnc string
		var deleted int
		if err := rows.Scan(&e.ID, &e.SortOrder, &e.Title, &e.Username, &e.URL, &e.Category, &pwEnc, &notesEnc, &e.CreatedAt, &e.UpdatedAt, &deleted); err != nil {
			return nil, err
		}
		if e.Password, err = crypto.AESDecryptString(s.EncKey, pwEnc); err != nil {
			return nil, err
		}
		if e.Notes, err = crypto.AESDecryptString(s.EncKey, notesEnc); err != nil {
			return nil, err
		}
		e.Deleted = deleted != 0
		list = append(list, e)
	}
	return list, rows.Err()
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

// handleImportEntries 批量导入 CSV 密码，返回导入条数。
func (s *Server) handleImportEntries(c *gin.Context) {
	claims := currentClaims(c)
	var req struct {
		CSV string `json:"csv"`
	}
	if err := readJSON(c, &req); err != nil {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	entries, err := csv.ParseCSVEntries([]byte(req.CSV))
	if err != nil {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	count := 0
	for _, e := range entries {
		if _, err := s.saveEntry(claims.UserID, e); err != nil {
			writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
		count++
	}
	log.LogAction(s.DB, claims.UserID, claims.Username, "import_entries", "导入密码 "+strconv.Itoa(count)+" 条", clientIP(c))
	writeJSON(c, http.StatusOK, gin.H{"count": count})
}

// handleImportText 从 TXT 批量导入密码。
func (s *Server) handleImportText(c *gin.Context) {
	claims := currentClaims(c)
	var req struct {
		Text string `json:"text"`
	}
	if err := readJSON(c, &req); err != nil {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	entries, err := csv.ParseTXTEntries([]byte(req.Text))
	if err != nil {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	count := 0
	for _, e := range entries {
		if _, err := s.saveEntry(claims.UserID, e); err != nil {
			writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
		count++
	}
	log.LogAction(s.DB, claims.UserID, claims.Username, "import_entries", "导入密码 "+strconv.Itoa(count)+" 条", clientIP(c))
	writeJSON(c, http.StatusOK, gin.H{"count": count})
}

// ---- 桌面客户端同步（整体上传/下载） ----

func (s *Server) handleGetVault(c *gin.Context) {
	claims := currentClaims(c)
	list, err := s.listEntriesAll(claims.UserID)
	if err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	writeJSON(c, http.StatusOK, gin.H{"entries": list})
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
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	log.LogAction(s.DB, claims.UserID, claims.Username, "upload_vault", "上传密码库 "+strconv.Itoa(len(req.Entries))+" 条", clientIP(c))
	writeJSON(c, http.StatusOK, gin.H{"status": "ok"})
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
	if req.Username == "" || len(req.Password) < 6 {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "用户名不能为空，密码至少 6 位"})
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
	email := req.Email
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
		if len(req.NewPassword) < 6 {
			writeJSON(c, http.StatusBadRequest, gin.H{"error": "新密码至少 6 位"})
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
		newHash, err := auth.HashPassword(req.NewPassword)
		if err != nil {
			writeJSON(c, http.StatusInternalServerError, gin.H{"error": "hash error"})
			return
		}
		if _, err := s.DB.Exec(`UPDATE users SET username=?, email=?, password_hash=? WHERE id=?`, username, req.Email, newHash, claims.UserID); err != nil {
			writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
	} else {
		if _, err := s.DB.Exec(`UPDATE users SET username=?, email=? WHERE id=?`, username, req.Email, claims.UserID); err != nil {
			writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
	}
	detail := "修改账号信息"
	if req.NewPassword != "" {
		detail = "修改密码"
	}
	log.LogAction(s.DB, claims.UserID, claims.Username, "update_me", detail, clientIP(c))
	writeJSON(c, http.StatusOK, gin.H{"status": "ok"})
}

// ---- 数据访问辅助 ----

func (s *Server) listEntries(userID int64) ([]db.Entry, error) {
	rows, err := s.DB.Query(`SELECT id, sort_order, title, username, url, category, password_enc, notes_enc, created_at, updated_at FROM entries WHERE user_id = ? AND deleted = 0 ORDER BY sort_order ASC, id ASC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []db.Entry{}
	for rows.Next() {
		var e db.Entry
		var pwEnc, notesEnc string
		if err := rows.Scan(&e.ID, &e.SortOrder, &e.Title, &e.Username, &e.URL, &e.Category, &pwEnc, &notesEnc, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, err
		}
		if e.Password, err = crypto.AESDecryptString(s.EncKey, pwEnc); err != nil {
			return nil, err
		}
		if e.Notes, err = crypto.AESDecryptString(s.EncKey, notesEnc); err != nil {
			return nil, err
		}
		list = append(list, e)
	}
	return list, rows.Err()
}

// listEntriesAll 返回该用户的全部条目（含墓碑），用于同步 vault 上传/下载。
func (s *Server) listEntriesAll(userID int64) ([]db.Entry, error) {
	rows, err := s.DB.Query(`SELECT id, sort_order, title, username, url, category, password_enc, notes_enc, created_at, updated_at, deleted FROM entries WHERE user_id = ? ORDER BY sort_order ASC, id ASC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []db.Entry{}
	for rows.Next() {
		var e db.Entry
		var pwEnc, notesEnc string
		var deleted int
		if err := rows.Scan(&e.ID, &e.SortOrder, &e.Title, &e.Username, &e.URL, &e.Category, &pwEnc, &notesEnc, &e.CreatedAt, &e.UpdatedAt, &deleted); err != nil {
			return nil, err
		}
		if e.Password, err = crypto.AESDecryptString(s.EncKey, pwEnc); err != nil {
			return nil, err
		}
		if e.Notes, err = crypto.AESDecryptString(s.EncKey, notesEnc); err != nil {
			return nil, err
		}
		e.Deleted = deleted != 0
		list = append(list, e)
	}
	return list, rows.Err()
}

func (s *Server) saveEntry(userID int64, e db.Entry) (db.Entry, error) {
	pwEnc, err := crypto.AESEncryptString(s.EncKey, e.Password)
	if err != nil {
		return e, err
	}
	notesEnc, err := crypto.AESEncryptString(s.EncKey, e.Notes)
	if err != nil {
		return e, err
	}
	now := time.Now().Format(time.RFC3339)
	if e.ID == 0 {
		e.CreatedAt = now
		e.UpdatedAt = now
		// 新条目追加到末尾（序号为当前最大序号 + 1）
		var maxSort int64
		_ = s.DB.QueryRow(`SELECT COALESCE(MAX(sort_order), 0) FROM entries WHERE user_id = ? AND deleted = 0`, userID).Scan(&maxSort)
		e.SortOrder = maxSort + 1
		res, err := s.DB.Exec(`INSERT INTO entries (sort_order, user_id, title, username, url, category, password_enc, notes_enc, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)`,
			e.SortOrder, userID, e.Title, e.Username, e.URL, e.Category, pwEnc, notesEnc, e.CreatedAt, e.UpdatedAt)
		if err != nil {
			return e, err
		}
		e.ID, _ = res.LastInsertId()
	} else {
		e.UpdatedAt = now
		_, err := s.DB.Exec(`UPDATE entries SET title=?, username=?, url=?, category=?, password_enc=?, notes_enc=?, updated_at=? WHERE id=? AND user_id=?`,
			e.Title, e.Username, e.URL, e.Category, pwEnc, notesEnc, e.UpdatedAt, e.ID, userID)
		if err != nil {
			return e, err
		}
	}
	return e, nil
}

func (s *Server) replaceEntries(userID int64, list []db.Entry) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM entries WHERE user_id = ?`, userID); err != nil {
		_ = tx.Rollback()
		return err
	}
	for _, e := range list {
		pwEnc, err := crypto.AESEncryptString(s.EncKey, e.Password)
		if err != nil {
			_ = tx.Rollback()
			return err
		}
		notesEnc, err := crypto.AESEncryptString(s.EncKey, e.Notes)
		if err != nil {
			_ = tx.Rollback()
			return err
		}
		deleted := 0
		if e.Deleted {
			deleted = 1
		}
		_, err = tx.Exec(`INSERT INTO entries (id, sort_order, user_id, title, username, url, category, password_enc, notes_enc, created_at, updated_at, deleted) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
			e.ID, e.SortOrder, userID, e.Title, e.Username, e.URL, e.Category, pwEnc, notesEnc, e.CreatedAt, e.UpdatedAt, deleted)
		if err != nil {
			_ = tx.Rollback()
			return err
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
	if err := auth.SendVerifyCode(s.DB, req.Email, "register"); err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	writeJSON(c, http.StatusOK, gin.H{"status": "ok"})
}

// handleSendResetCode 发送密码重置验证码。
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
	var id int64
	err := s.DB.QueryRow(`SELECT id FROM users WHERE email = ?`, req.Email).Scan(&id)
	if err == sql.ErrNoRows {
		writeJSON(c, http.StatusNotFound, gin.H{"error": "该邮箱未注册"})
		return
	}
	if err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	if err := auth.SendVerifyCode(s.DB, req.Email, "reset"); err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	writeJSON(c, http.StatusOK, gin.H{"status": "ok"})
}

// handleResetPassword 重置密码。
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
	if req.Email == "" || len(req.Password) < 6 {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "邮箱不能为空，新密码至少 6 位"})
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
	res, err := s.DB.Exec(`UPDATE users SET password_hash = ? WHERE email = ?`, hash, req.Email)
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
		"password_require_complex": db.GetMeta(s.DB, "password_require_complex") == "true",
		"default_language":         defaultLanguage(s.DB),
		"site":                     db.LoadSiteConfig(s.DB),
	})
}

// handleGetSettings 返回系统设置（SMTP 配置 + 邮箱验证模式 + 站点信息）。
func (s *Server) handleGetSettings(c *gin.Context) {
	writeJSON(c, http.StatusOK, gin.H{
		"smtp":                     auth.LoadSMTPConfig(s.DB),
		"smtp_enabled":             auth.SMTPEnabled(s.DB),
		"email_verify_mode":        auth.EmailVerifyMode(s.DB),
		"allow_registration":       db.GetMeta(s.DB, "allow_registration") == "true",
		"password_min_length":      auth.PasswordMinLength(s.DB),
		"password_require_complex": db.GetMeta(s.DB, "password_require_complex") == "true",
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
	if req.Password != "" {
		_ = db.SetMeta(s.DB, "smtp_password", req.Password)
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
	if err := auth.SendHTMLEmail(s.DB, req.Email, "密匣 CryPtBox 测试邮件", auth.TestEmailHTML()); err != nil {
		writeJSON(c, http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
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
	ext := strings.TrimPrefix(strings.ToLower(filepath.Ext(p)), ".")
	ct := "image/" + ext
	if ext == "svg" {
		ct = "image/svg+xml"
	} else if ext == "jpg" {
		ct = "image/jpeg"
	}
	c.Header("Cache-Control", "no-cache")
	c.Data(http.StatusOK, ct, data)
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
	ext := strings.ToLower(strings.TrimPrefix(req.Ext, "."))
	allowed := map[string]bool{"png": true, "jpg": true, "jpeg": true, "gif": true, "svg": true, "webp": true}
	if !allowed[ext] {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "不支持的图片格式"})
		return
	}
	if len(data) > 2*1024*1024 {
		writeJSON(c, http.StatusBadRequest, gin.H{"error": "图片不能超过 2MB"})
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
