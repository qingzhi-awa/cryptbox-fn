package handlers

import (
	"net/http"
	"testing"

	"github.com/qingzhi-awa/cryptbox/shared/auth"
	"github.com/qingzhi-awa/cryptbox/shared/db"
)

// TestTokenVersionInvalidatedOnPasswordChange 验证 PT-06 的令牌吊销能力：
//
//  1. 用户改自己的密码 → 该用户此前签发的令牌立即 401；
//  2. 响应中新签发的令牌仍然可用（不会把用户自己登出）；
//  3. 管理员改他人密码 → 被改用户此前签发的令牌立即 401。
func TestTokenVersionInvalidatedOnPasswordChange(t *testing.T) {
	r, database := newTestServer(t)

	// 1) 初始化超管并创建普通用户。
	code, resp := doJSON(t, r, http.MethodPost, "/api/setup", "", map[string]any{
		"username": "admin", "password": "AdminPass123",
	})
	if code != http.StatusOK {
		t.Fatalf("setup: code=%d resp=%v", code, resp)
	}
	adminToken, _ := resp["token"].(string)

	tokenU := createUserAndLogin(t, r, adminToken, "tvuser", "UserTvPass1")

	// 初始令牌可用。
	if code, _ := doJSON(t, r, http.MethodGet, "/api/me", tokenU, nil); code != http.StatusOK {
		t.Fatalf("改密前 token 应可用，实际 %d", code)
	}

	// 2) 用户自行改密（superadmin 之外的用户走 ValidatePassword：≥6 位 + 字母数字）。
	code, resp = doJSON(t, r, http.MethodPost, "/api/me/update", tokenU, map[string]any{
		"username":         "tvuser",
		"current_password": "UserTvPass1",
		"new_password":     "UserTvPass2",
	})
	if code != http.StatusOK {
		t.Fatalf("改密失败: code=%d resp=%v", code, resp)
	}
	fresh, _ := resp["token"].(string)
	if fresh == "" {
		t.Fatal("改密后应为当前会话重新签发令牌，否则用户会被自己登出")
	}

	// 3) 旧令牌必须立即失效，新令牌必须可用。
	if code, _ := doJSON(t, r, http.MethodGet, "/api/me", tokenU, nil); code != http.StatusUnauthorized {
		t.Fatalf("改密后旧令牌应 401，实际 %d", code)
	}
	if code, _ := doJSON(t, r, http.MethodGet, "/api/me", fresh, nil); code != http.StatusOK {
		t.Fatalf("改密后新令牌应可用，实际 %d", code)
	}

	// 令牌版本确实递增了。
	var userID int64
	if err := database.QueryRow(`SELECT id FROM users WHERE username = 'tvuser'`).Scan(&userID); err != nil {
		t.Fatalf("read user: %v", err)
	}
	if v := db.TokenVersion(database, userID); v != 1 {
		t.Fatalf("改密后 token_version 应为 1，实际 %d", v)
	}
	claims, err := auth.ParseToken("unit-test-jwt-secret", fresh)
	if err != nil {
		t.Fatalf("解析新令牌失败: %v", err)
	}
	if claims.TokenVer != 1 {
		t.Fatalf("新令牌 ver 应为 1，实际 %d", claims.TokenVer)
	}

	// 4) 管理员改他人密码 → 该用户令牌失效。
	code, resp = doJSON(t, r, http.MethodPost, "/api/users/update?id="+itoa64(userID), adminToken, map[string]any{
		"username": "tvuser", "password": "UserTvPass3", "role": "user", "status": "active",
	})
	if code != http.StatusOK {
		t.Fatalf("管理员改密失败: code=%d resp=%v", code, resp)
	}
	if code, _ := doJSON(t, r, http.MethodGet, "/api/me", fresh, nil); code != http.StatusUnauthorized {
		t.Fatalf("管理员改密后该用户旧令牌应 401，实际 %d", code)
	}
	if v := db.TokenVersion(database, userID); v != 2 {
		t.Fatalf("管理员改密后 token_version 应为 2，实际 %d", v)
	}

	// 5) 改密后旧密码不再可用、新密码可登录。
	if code, _ := doJSON(t, r, http.MethodPost, "/api/login", "", map[string]any{
		"username": "tvuser", "password": "UserTvPass2",
	}); code != http.StatusUnauthorized {
		t.Fatalf("旧密码应登录失败，实际 %d", code)
	}
	code, resp = doJSON(t, r, http.MethodPost, "/api/login", "", map[string]any{
		"username": "tvuser", "password": "UserTvPass3",
	})
	if code != http.StatusOK {
		t.Fatalf("新密码应登录成功，实际 %d resp=%v", code, resp)
	}
}

// itoa64 极简整数转字符串（测试内使用，避免额外 import）。
func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
