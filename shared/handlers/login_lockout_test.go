package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// doJSONFromIP 与 doJSON 相同，但显式指定来源 IP（用于验证限流/锁定是否跨来源放大）。
func doJSONFromIP(t *testing.T, r http.Handler, ip, method, path, token string, body any) (int, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = ip + ":45678"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// mustLogin 登录并返回 token，失败即终止测试。
func mustLogin(t *testing.T, r http.Handler, username, password string) string {
	t.Helper()
	code, resp := doJSON(t, r, http.MethodPost, "/api/login", "", map[string]any{
		"username": username, "password": password,
	})
	if code != http.StatusOK {
		t.Fatalf("login %s failed: code=%d resp=%v", username, code, resp)
	}
	tok, _ := resp["token"].(string)
	if tok == "" {
		t.Fatalf("login %s 未返回 token", username)
	}
	return tok
}

// R6-01：账号维度失败锁定可被定向 DoS。
//
// 攻击者只需知道受害者用户名，用 5 次错误密码即可把该账号锁定 15 分钟；
// 且锁定到期后可立即再打 5 次续锁，形成持续拒绝服务——受害者本人
// （即使密码正确）在此期间也无法登录。
//
// 期望行为：来自**不同 IP** 的失败尝试不应直接锁死该账号对**其他来源**的可用性
// （锁定键应包含来源维度，例如 IP+账号）。
func TestLoginLockoutIsNotGloballyAmplified(t *testing.T) {
	r, _ := newTestServer(t)
	if code, _ := doJSON(t, r, "POST", "/api/setup", "", gin.H{
		"username": "admin", "password": "AdminPass123",
	}); code != http.StatusOK {
		t.Fatalf("setup failed: %d", code)
	}
	adminTok := mustLogin(t, r, "admin", "AdminPass123")

	// 建一个普通受害用户。
	if code, resp := doJSON(t, r, "POST", "/api/users", adminTok, gin.H{
		"username": "victim", "password": "VictimPass123", "role": "user",
		"email": "victim@example.com",
	}); code != http.StatusOK {
		t.Fatalf("create victim failed: %d (%v)", code, resp)
	}

	// 攻击者从 IP A 用错误密码打 5 次。
	for i := 0; i < 5; i++ {
		code, _ := doJSONFromIP(t, r, "10.0.0.9", "POST", "/api/login", "", gin.H{
			"username": "victim", "password": "wrong-password",
		})
		if code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i+1, code)
		}
	}

	// 受害者从**自己的 IP B** 用**正确密码**登录，应成功。
	// 若被 429 拒绝，说明账号锁定被跨来源放大成 DoS。
	code, body := doJSONFromIP(t, r, "192.168.1.50", "POST", "/api/login", "", gin.H{
		"username": "victim", "password": "VictimPass123",
	})
	if code == http.StatusTooManyRequests {
		t.Fatalf("账号锁定被跨 IP 放大：受害者从自己 IP 用正确密码仍被拒（%v）", body)
	}
	if code != http.StatusOK {
		t.Fatalf("受害者正确登录应返回 200，实际 %d（%v）", code, body)
	}
}

// 反向验证：**同一来源 IP** 的连续失败仍应被锁定（防暴力破解能力不能被削弱）。
func TestLoginLockoutStillAppliesPerSource(t *testing.T) {
	r, _ := newTestServer(t)
	if code, _ := doJSON(t, r, "POST", "/api/setup", "", gin.H{
		"username": "admin", "password": "AdminPass123",
	}); code != http.StatusOK {
		t.Fatalf("setup failed: %d", code)
	}
	for i := 0; i < 5; i++ {
		doJSONFromIP(t, r, "10.1.1.1", "POST", "/api/login", "", gin.H{
			"username": "admin", "password": "wrong",
		})
	}
	// 第 6 次同 IP 必须被锁。
	code, _ := doJSONFromIP(t, r, "10.1.1.1", "POST", "/api/login", "", gin.H{
		"username": "admin", "password": "AdminPass123",
	})
	if code != http.StatusTooManyRequests {
		t.Fatalf("同一来源连续失败应被锁定（期望 429），实际 %d", code)
	}
}
