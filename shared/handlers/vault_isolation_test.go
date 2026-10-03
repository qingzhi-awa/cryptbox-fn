package handlers

import (
	"fmt"
	"net/http"
	"testing"
)

// entryBody 构造一条端到端加密条目（服务端只做不透明存储）。
func entryBody(id int64, title string) map[string]any {
	return map[string]any{
		"id":         id,
		"sort_order": id,
		"title":      title,
		"username":   "u",
		"password":   "enc-pw",
		"url":        "https://example.com",
		"category":   "cat",
		"notes":      "",
		"created_at": "2026-10-03T00:00:00Z",
		"updated_at": "2026-10-03T00:00:00Z",
		"deleted":    false,
	}
}

// createUserAndLogin 用管理员令牌创建普通用户并返回其登录令牌。
func createUserAndLogin(t *testing.T, r http.Handler, adminToken, username, password string) string {
	t.Helper()
	code, resp := doJSON(t, r, http.MethodPost, "/api/users", adminToken, map[string]any{
		"username": username, "password": password, "email": username + "@test.com",
	})
	if code != http.StatusOK {
		t.Fatalf("创建用户 %s 失败: code=%d resp=%v", username, code, resp)
	}
	code, resp = doJSON(t, r, http.MethodPost, "/api/login", "", map[string]any{
		"username": username, "password": password,
	})
	if code != http.StatusOK {
		t.Fatalf("登录 %s 失败: code=%d resp=%v", username, code, resp)
	}
	token, _ := resp["token"].(string)
	if token == "" {
		t.Fatalf("登录 %s 未返回 token", username)
	}
	return token
}

// TestCrossUserEntryIDIsolation 回归 PT-01：
// 不同用户使用相同 id 上传密码库必须各自成功（此前第二个用户必然 500 且完全无法同步）。
func TestCrossUserEntryIDIsolation(t *testing.T) {
	r, _ := newTestServer(t)

	code, resp := doJSON(t, r, http.MethodPost, "/api/setup", "", map[string]any{
		"username": "admin", "password": "AdminPass123",
	})
	if code != http.StatusOK {
		t.Fatalf("setup: code=%d resp=%v", code, resp)
	}
	adminToken, _ := resp["token"].(string)

	tokenA := createUserAndLogin(t, r, adminToken, "usera", "UserAPass1")
	tokenB := createUserAndLogin(t, r, adminToken, "userb", "UserBPass1")
	tokenC := createUserAndLogin(t, r, adminToken, "userc", "UserCPass1")

	// userA 先占用 id=1,2,3（模拟客户端本地自增 id 从 1 开始）
	code, resp = doJSON(t, r, http.MethodPut, "/api/vault", tokenA, map[string]any{
		"entries": []any{entryBody(1, "userA-1"), entryBody(2, "userA-2"), entryBody(3, "userA-3")},
	})
	if code != http.StatusOK {
		t.Fatalf("userA 上传失败: code=%d resp=%v", code, resp)
	}

	// userB / userC 使用同样的 id 也必须成功
	for name, token := range map[string]string{"userB": tokenB, "userC": tokenC} {
		code, resp = doJSON(t, r, http.MethodPut, "/api/vault", token, map[string]any{
			"entries": []any{entryBody(1, name + "-1"), entryBody(2, name + "-2")},
		})
		if code != http.StatusOK {
			t.Fatalf("%s 使用相同 id 上传应成功，实际 code=%d resp=%v", name, code, resp)
		}
	}

	// 各自只能看到自己的条目
	for name, token := range map[string]string{"userA": tokenA, "userB": tokenB, "userC": tokenC} {
		code, resp = doJSON(t, r, http.MethodGet, "/api/vault", token, nil)
		if code != http.StatusOK {
			t.Fatalf("%s 拉取失败: code=%d", name, code)
		}
		entries, _ := resp["entries"].([]any)
		if len(entries) == 0 {
			t.Fatalf("%s 应能看到自己的条目", name)
		}
		for _, e := range entries {
			m, _ := e.(map[string]any)
			title, _ := m["title"].(string)
			if len(title) == 0 {
				t.Fatalf("%s 条目缺少标题", name)
			}
			if want := name + "-"; len(title) < len(want) || title[:len(want)] != want {
				t.Fatalf("%s 看到了不属于自己的条目: %q", name, title)
			}
		}
	}
}

// TestDuplicateIDsInOneUpload 同一请求内重复 id 应被去重（保留最后一条），而不是整批失败。
func TestDuplicateIDsInOneUpload(t *testing.T) {
	r, _ := newTestServer(t)

	code, resp := doJSON(t, r, http.MethodPost, "/api/setup", "", map[string]any{
		"username": "admin", "password": "AdminPass123",
	})
	if code != http.StatusOK {
		t.Fatalf("setup: code=%d resp=%v", code, resp)
	}
	token, _ := resp["token"].(string)

	code, resp = doJSON(t, r, http.MethodPut, "/api/vault", token, map[string]any{
		"entries": []any{entryBody(7, "first"), entryBody(7, "second"), entryBody(8, "other")},
	})
	if code != http.StatusOK {
		t.Fatalf("重复 id 上传应被去重后成功，实际 code=%d resp=%v", code, resp)
	}
	code, resp = doJSON(t, r, http.MethodGet, "/api/vault", token, nil)
	if code != http.StatusOK {
		t.Fatalf("拉取失败: code=%d", code)
	}
	entries, _ := resp["entries"].([]any)
	if len(entries) != 2 {
		t.Fatalf("去重后应有 2 条，实际 %d", len(entries))
	}
}

// TestStatusVersionRequiresAuth 回归 PT-13：未认证只返回 build 摘要，认证后才返回精确版本号。
func TestStatusVersionRequiresAuth(t *testing.T) {
	r, _ := newTestServer(t)

	code, resp := doJSON(t, r, http.MethodGet, "/api/status", "", nil)
	if code != http.StatusOK {
		t.Fatalf("status: code=%d", code)
	}
	if _, ok := resp["version"]; ok {
		t.Fatal("未认证请求不应返回精确版本号")
	}
	if build, _ := resp["build"].(string); build == "" {
		t.Fatal("未认证请求应返回 build 摘要供前端自检")
	}

	code, resp = doJSON(t, r, http.MethodPost, "/api/setup", "", map[string]any{
		"username": "admin", "password": "AdminPass123",
	})
	if code != http.StatusOK {
		t.Fatalf("setup: code=%d resp=%v", code, resp)
	}
	token, _ := resp["token"].(string)

	code, resp = doJSON(t, r, http.MethodGet, "/api/status", token, nil)
	if code != http.StatusOK {
		t.Fatalf("status(authed): code=%d", code)
	}
	if _, ok := resp["version"]; !ok {
		t.Fatal("已认证请求应返回精确版本号")
	}
}

// TestSuperAdminPasswordPolicy 回归 PT-12：超级管理员口令需满足长度与复杂度要求。
func TestSuperAdminPasswordPolicy(t *testing.T) {
	r, _ := newTestServer(t)

	cases := []struct {
		password string
		wantOK   bool
		desc     string
	}{
		{"admin123", false, "仅 8 位（低于 10 位下限）"},
		{"abcdefghij", false, "无数字"},
		{"1234567890", false, "无字母"},
		{"AdminPass123", true, "10 位以上且含字母数字"},
	}
	for i, c := range cases {
		code, resp := doJSON(t, r, http.MethodPost, "/api/setup", "", map[string]any{
			"username": fmt.Sprintf("root%d", i), "password": c.password,
		})
		got := code == http.StatusOK
		if got != c.wantOK {
			t.Fatalf("口令 %q（%s）期望 ok=%v，实际 code=%d resp=%v", c.password, c.desc, c.wantOK, code, resp)
		}
	}
}
