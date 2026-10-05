package handlers

import (
	"net/http"
	"testing"
	"time"

	"github.com/qingzhi-awa/cryptbox/shared/auth"
	"github.com/qingzhi-awa/cryptbox/shared/db"
)

// F1/F2/F3/F5 回归测试（第三方审计发现项）。
//
// 共同根因：把 JWT 声明（username）当作账号事实源，以及邮箱锚点大小写不敏感。
// 修复后：authMiddleware 每请求比对 DB 现值（username / created_at），
// handleUpdateMe 以 DB 现值回填，注册拒绝保留名，邮箱唯一性按 lower(email) 归一。

// setupAdminLogin 初始化超管并返回其令牌（封装重复步骤）。
func setupAdminLogin(t *testing.T, r http.Handler) string {
	t.Helper()
	if code, resp := doJSON(t, r, http.MethodPost, "/api/setup", "", map[string]any{
		"username": "admin", "password": "AdminPass123",
	}); code != http.StatusOK {
		t.Fatalf("setup 失败: code=%d resp=%v", code, resp)
	}
	code, resp := doJSON(t, r, http.MethodPost, "/api/login", "", map[string]any{
		"username": "admin", "password": "AdminPass123",
	})
	if code != http.StatusOK {
		t.Fatalf("超管登录失败: code=%d resp=%v", code, resp)
	}
	token, _ := resp["token"].(string)
	if token == "" {
		t.Fatal("超管登录未返回令牌")
	}
	return token
}

// TestF1StaleTokenBlockedAfterIDReuse 验证：被删账号的陈旧令牌不会复活到
// 「复用同一 id」的新账号上（账号接管/提权链被切断）。
func TestF1StaleTokenBlockedAfterIDReuse(t *testing.T) {
	r, _ := newTestServer(t)
	adminToken := setupAdminLogin(t, r)

	// 建 victim（id=2）并登录取旧令牌。
	victimToken := createUserAndLogin(t, r, adminToken, "victim", "VictimPass1")
	if code, _ := doJSON(t, r, http.MethodGet, "/api/me", victimToken, nil); code != http.StatusOK {
		t.Fatalf("victim 令牌应可用，实际 %d", code)
	}
	// 删除 victim —— id=2 被回收。
	if code, _ := doJSON(t, r, http.MethodDelete, "/api/users/2", adminToken, nil); code != http.StatusOK {
		t.Fatal("删除 victim 失败")
	}
	// 删除后 DB 无该行，旧令牌立即 401（正常）。
	if code, _ := doJSON(t, r, http.MethodGet, "/api/me", victimToken, nil); code != http.StatusUnauthorized {
		t.Errorf("删号后旧令牌应 401，实际 %d", code)
	}
	// 建 newbie 复用 id=2：旧令牌不得复活（用户名已变）。
	if code, resp := doJSON(t, r, http.MethodPost, "/api/users", adminToken, map[string]any{
		"username": "newbie", "password": "NewbiePass1", "email": "newbie@test.com",
	}); code != http.StatusOK {
		t.Fatalf("创建 newbie 失败: code=%d resp=%v", code, resp)
	}
	if code, _ := doJSON(t, r, http.MethodGet, "/api/me", victimToken, nil); code != http.StatusUnauthorized {
		t.Fatalf("ID 被复用后旧令牌必须 401（用户名不同），实际 %d", code)
	}

	// 同名复用：删 newbie，再建名为 victim 的账号（仍复用 id=2）。
	// 此时用户名与旧令牌一致，唯一能拦下它的是「令牌签发时间早于账号创建时间」。
	// created_at 为秒级精度，先跨过 1 秒边界以保证判定确定。
	if code, _ := doJSON(t, r, http.MethodDelete, "/api/users/2", adminToken, nil); code != http.StatusOK {
		t.Fatal("删除 newbie 失败")
	}
	time.Sleep(1100 * time.Millisecond)
	if code, resp := doJSON(t, r, http.MethodPost, "/api/users", adminToken, map[string]any{
		"username": "victim", "password": "VictimPass2", "email": "victim2@test.com",
	}); code != http.StatusOK {
		t.Fatalf("同名重建 victim 失败: code=%d resp=%v", code, resp)
	}
	if code, _ := doJSON(t, r, http.MethodGet, "/api/me", victimToken, nil); code != http.StatusUnauthorized {
		t.Fatalf("同名账号复用 id 后，更早签发的旧令牌必须 401，实际 %d", code)
	}
}

// TestF2SelfRenameDoesNotRollBack 验证：改名后既不会因令牌内的旧用户名把身份
// 回滚（F2），也不会让旧令牌继续可用。
func TestF2SelfRenameDoesNotRollBack(t *testing.T) {
	r, _ := newTestServer(t)
	adminToken := setupAdminLogin(t, r)
	tok := createUserAndLogin(t, r, adminToken, "alice", "AlicePass1")

	// 自助改名需当前口令；成功后应为当前会话重新签发令牌。
	code, resp := doJSON(t, r, http.MethodPut, "/api/me", tok, map[string]any{
		"username": "alice_new", "current_password": "AlicePass1",
	})
	if code != http.StatusOK {
		t.Fatalf("自助改名失败: code=%d resp=%v", code, resp)
	}
	fresh, _ := resp["token"].(string)
	if fresh == "" {
		t.Fatal("改名后应为当前会话重新签发令牌，否则用户会被自己登出")
	}
	// 旧令牌立即失效。
	if code, _ := doJSON(t, r, http.MethodGet, "/api/me", tok, nil); code != http.StatusUnauthorized {
		t.Errorf("改名后旧令牌应 401，实际 %d", code)
	}
	// 空 body 的 PUT /api/me 不得把用户名回滚为旧值（F2：回填以 DB 现值为准）。
	if code, _ := doJSON(t, r, http.MethodPut, "/api/me", fresh, map[string]any{}); code != http.StatusOK {
		t.Fatalf("空 body 更新应 200，实际 %d", code)
	}
	_, me := doJSON(t, r, http.MethodGet, "/api/me", fresh, nil)
	if got, _ := me["username"].(string); got != "alice_new" {
		t.Fatalf("用户名被回滚：期望 alice_new，实际 %q", got)
	}
}

// TestF3RegisterRejectsReservedUsernames 验证：公开注册不得占用系统保留名。
func TestF3RegisterRejectsReservedUsernames(t *testing.T) {
	r, database := newTestServer(t)
	// 打开注册：需 allow_registration + 已配置并启用的 SMTP。
	for k, v := range map[string]string{
		"allow_registration": "true",
		"smtp_enabled":       "true",
		"smtp_host":          "smtp.example.com",
		"smtp_port":          "465",
	} {
		if err := db.SetMeta(database, k, v); err != nil {
			t.Fatalf("设置 meta %s 失败: %v", k, err)
		}
	}
	// 注入验证码（绕过真实发信）。保留名分支在消费验证码之前返回，故可复用同一码。
	if err := auth.SaveVerification(database, "reg@test.com", "123456", "register"); err != nil {
		t.Fatalf("写入验证码失败: %v", err)
	}
	for _, name := range []string{"admin", "ROOT", "superadmin", "system"} {
		code, resp := doJSON(t, r, http.MethodPost, "/api/register", "", map[string]any{
			"username": name, "password": "Passw0rd1", "email": "reg@test.com", "code": "123456",
		})
		if code != http.StatusBadRequest {
			t.Errorf("注册保留名 %q 应 400，实际 %d resp=%v", name, code, resp)
		}
	}
	// 对照：普通用户名 + 正确验证码 → 200。
	if code, resp := doJSON(t, r, http.MethodPost, "/api/register", "", map[string]any{
		"username": "normaluser", "password": "Passw0rd1", "email": "reg@test.com", "code": "123456",
	}); code != http.StatusOK {
		t.Fatalf("普通用户名注册应 200，实际 %d resp=%v", code, resp)
	}
}

// TestF5EmailCaseInsensitiveUniqueness 验证：邮箱唯一性大小写不敏感
// （写入口归一 + 表达式唯一索引 + 邮箱登录不区分大小写）。
func TestF5EmailCaseInsensitiveUniqueness(t *testing.T) {
	r, database := newTestServer(t)
	adminToken := setupAdminLogin(t, r)

	// 管理员以混合大小写邮箱建 u1：应成功且落库归一为小写。
	if code, resp := doJSON(t, r, http.MethodPost, "/api/users", adminToken, map[string]any{
		"username": "caseuser1", "password": "CasePass11", "email": "CaseDup@X.com",
	}); code != http.StatusOK {
		t.Fatalf("创建 caseuser1 失败: code=%d resp=%v", code, resp)
	}
	var stored string
	if err := database.QueryRow(`SELECT email FROM users WHERE username = 'caseuser1'`).Scan(&stored); err != nil {
		t.Fatalf("读取邮箱失败: %v", err)
	}
	if stored != "casedup@x.com" {
		t.Errorf("邮箱应归一为小写，实际 %q", stored)
	}
	// 同一邮箱仅大小写不同 → 必须 409。
	if code, resp := doJSON(t, r, http.MethodPost, "/api/users", adminToken, map[string]any{
		"username": "caseuser2", "password": "CasePass22", "email": "casedup@x.com",
	}); code != http.StatusConflict {
		t.Errorf("大小写不同的同一邮箱应 409，实际 %d resp=%v", code, resp)
	}
	// 用大小写变体经邮箱登录应成功。
	if code, _ := doJSON(t, r, http.MethodPost, "/api/login", "", map[string]any{
		"username": "CASEDUP@X.COM", "password": "CasePass11",
	}); code != http.StatusOK {
		t.Errorf("大小写变体邮箱登录应成功，实际 %d", code)
	}
	// 唯一索引须大小写不敏感：直接插入不同大小写的同邮箱必须被拒。
	if _, err := database.Exec(`INSERT INTO users (id, username, password_hash, role, status, email) VALUES (1000, 'rawdup', 'x', 'user', 'active', 'CASEDUP@X.COM')`); err == nil {
		t.Fatal("唯一索引应为大小写不敏感，混合大小写重复邮箱插入应失败")
	}
}
