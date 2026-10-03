package handlers

import (
	"net/http"
	"testing"

	"github.com/qingzhi-awa/cryptbox/shared/uuid"
)

// entryWithUUID 构造带指定 uuid 的端到端加密条目（服务端只做不透明存储）。
func entryWithUUID(id int64, u, title string) map[string]any {
	return map[string]any{
		"id":         id,
		"uuid":       u,
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

func fetchVault(t *testing.T, r http.Handler, token string) []map[string]any {
	t.Helper()
	code, resp := doJSON(t, r, http.MethodGet, "/api/vault", token, nil)
	if code != http.StatusOK {
		t.Fatalf("GET /api/vault: code=%d resp=%v", code, resp)
	}
	raw, _ := resp["entries"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, it := range raw {
		if m, ok := it.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// TestEntryUUIDRoundTrip 校验 PT-04：客户端自带的 uuid 被原样保存与下发
// （身份不再依赖本地自增 id）。
func TestEntryUUIDRoundTrip(t *testing.T) {
	r, _ := newTestServer(t)
	code, resp := doJSON(t, r, http.MethodPost, "/api/setup", "", map[string]any{
		"username": "admin", "password": "AdminPass123",
	})
	if code != http.StatusOK {
		t.Fatalf("setup: code=%d resp=%v", code, resp)
	}
	adminToken, _ := resp["token"].(string)
	token := createUserAndLogin(t, r, adminToken, "uu1", "UserUuPass1")

	uA := "aaaaaaaa-1111-4111-8111-111111111111"
	uB := "bbbbbbbb-2222-4222-8222-222222222222"
	code, resp = doJSON(t, r, http.MethodPut, "/api/vault", token, map[string]any{
		"entries": []any{entryWithUUID(1, uA, "Gmail"), entryWithUUID(2, uB, "GitHub")},
	})
	if code != http.StatusOK {
		t.Fatalf("上传失败: code=%d resp=%v", code, resp)
	}
	list := fetchVault(t, r, token)
	got := map[int64]string{}
	for _, e := range list {
		id, _ := e["id"].(float64)
		u, _ := e["uuid"].(string)
		got[int64(id)] = u
	}
	if got[1] != uA || got[2] != uB {
		t.Fatalf("uuid 未被原样保留: %v", got)
	}
}

// TestEntryUUIDBackfilledForLegacyClient 旧版客户端（不带 uuid）上传后，
// 服务端按 (user_id, id) 分配确定性 uuid，且重复上传结果稳定。
func TestEntryUUIDBackfilledForLegacyClient(t *testing.T) {
	r, database := newTestServer(t)
	code, resp := doJSON(t, r, http.MethodPost, "/api/setup", "", map[string]any{
		"username": "admin", "password": "AdminPass123",
	})
	if code != http.StatusOK {
		t.Fatalf("setup: code=%d resp=%v", code, resp)
	}
	adminToken, _ := resp["token"].(string)
	token := createUserAndLogin(t, r, adminToken, "uu2", "UserUuPass2")

	var userID int64
	if err := database.QueryRow(`SELECT id FROM users WHERE username = 'uu2'`).Scan(&userID); err != nil {
		t.Fatalf("read user id: %v", err)
	}

	// 不带 uuid 上传（模拟旧客户端）。
	legacy := entryWithUUID(7, "", "Legacy")
	delete(legacy, "uuid")
	code, resp = doJSON(t, r, http.MethodPut, "/api/vault", token, map[string]any{
		"entries": []any{legacy},
	})
	if code != http.StatusOK {
		t.Fatalf("上传失败: code=%d resp=%v", code, resp)
	}
	want := uuid.Deterministic(userID, 7)
	list := fetchVault(t, r, token)
	if len(list) != 1 {
		t.Fatalf("应返回 1 条，实际 %d", len(list))
	}
	if got, _ := list[0]["uuid"].(string); got != want {
		t.Fatalf("确定性 uuid 应为 %q，实际 %q", want, got)
	}

	// 再次上传同一旧条目：uuid 必须稳定（幂等）。
	if code, resp = doJSON(t, r, http.MethodPut, "/api/vault", token, map[string]any{
		"entries": []any{legacy},
	}); code != http.StatusOK {
		t.Fatalf("二次上传失败: code=%d resp=%v", code, resp)
	}
	list = fetchVault(t, r, token)
	if got, _ := list[0]["uuid"].(string); got != want {
		t.Fatalf("重复上传后 uuid 不应变化：%q → %q", want, got)
	}
}

// TestEntryUUIDDedupeAndIdReassign 同请求内重复 uuid 去重；
// 不同 uuid 撞同一 id 时重分配 id，避免静默丢数据。
func TestEntryUUIDDedupeAndIdReassign(t *testing.T) {
	r, _ := newTestServer(t)
	code, resp := doJSON(t, r, http.MethodPost, "/api/setup", "", map[string]any{
		"username": "admin", "password": "AdminPass123",
	})
	if code != http.StatusOK {
		t.Fatalf("setup: code=%d resp=%v", code, resp)
	}
	adminToken, _ := resp["token"].(string)
	token := createUserAndLogin(t, r, adminToken, "uu3", "UserUuPass3")

	uA := "cccccccc-3333-4333-8333-333333333333"
	uB := "dddddddd-4444-4444-8444-444444444444"

	// 重复 uuid（同 uuid 出现两次，标题不同）→ 保留最后一条。
	code, resp = doJSON(t, r, http.MethodPut, "/api/vault", token, map[string]any{
		"entries": []any{
			entryWithUUID(1, uA, "旧标题"),
			entryWithUUID(1, uA, "新标题"),
		},
	})
	if code != http.StatusOK {
		t.Fatalf("上传失败: code=%d resp=%v", code, resp)
	}
	list := fetchVault(t, r, token)
	if len(list) != 1 {
		t.Fatalf("重复 uuid 应去重为 1 条，实际 %d", len(list))
	}
	if title, _ := list[0]["title"].(string); title != "新标题" {
		t.Fatalf("应保留最后一条，实际标题 %q", title)
	}

	// 不同 uuid 撞同一 id → 两件都要保留，且 id 必须互不相同（服务端主键）。
	code, resp = doJSON(t, r, http.MethodPut, "/api/vault", token, map[string]any{
		"entries": []any{entryWithUUID(5, uA, "设备A条目"), entryWithUUID(5, uB, "设备B条目")},
	})
	if code != http.StatusOK {
		t.Fatalf("上传失败: code=%d resp=%v", code, resp)
	}
	list = fetchVault(t, r, token)
	if len(list) != 2 {
		t.Fatalf("不同 uuid 的条目都应保留，实际 %d 条", len(list))
	}
	ids := map[int64]bool{}
	for _, e := range list {
		id, _ := e["id"].(float64)
		if ids[int64(id)] {
			t.Fatalf("id 重复：%v", id)
		}
		ids[int64(id)] = true
	}
}

// TestEntryUUIDCrossUserIsolation 不同用户可使用相同 uuid（唯一索引按用户隔离）。
func TestEntryUUIDCrossUserIsolation(t *testing.T) {
	r, _ := newTestServer(t)
	code, resp := doJSON(t, r, http.MethodPost, "/api/setup", "", map[string]any{
		"username": "admin", "password": "AdminPass123",
	})
	if code != http.StatusOK {
		t.Fatalf("setup: code=%d resp=%v", code, resp)
	}
	adminToken, _ := resp["token"].(string)
	tA := createUserAndLogin(t, r, adminToken, "uu4", "UserUuPass4")
	tB := createUserAndLogin(t, r, adminToken, "uu5", "UserUuPass5")

	shared := "eeeeeeee-5555-4555-8555-555555555555"
	for i, tok := range []string{tA, tB} {
		code, resp = doJSON(t, r, http.MethodPut, "/api/vault", tok, map[string]any{
			"entries": []any{entryWithUUID(1, shared, "同名条目")},
		})
		if code != http.StatusOK {
			t.Fatalf("用户%d 上传失败: code=%d resp=%v", i+1, code, resp)
		}
		if list := fetchVault(t, r, tok); len(list) != 1 {
			t.Fatalf("用户%d 应看到 1 条，实际 %d", i+1, len(list))
		}
	}
}
