package handlers

import (
	"net/http"
	"testing"

	"github.com/qingzhi-awa/cryptbox/shared/db"
)

// TestLegacyMarkerIsPerUser 锁定 PT：legacy 迁移标记必须**按用户隔离**。
//
// 回归背景：早期实现把标记写成全局 meta 键 `legacy_migration_done`，导致任一用户
// （哪怕是最普通的账号）调用一次 POST /api/vault/legacy/done，就把**全服务器所有用户**
// 的 legacy 迁移接口一起封死（410 Gone），其他人重置密码后永久无法迁移旧数据。
func TestLegacyMarkerIsPerUser(t *testing.T) {
	r, _ := newTestServer(t)

	// 建 admin，并创建两个普通用户 bob / carol。
	if code, _ := doJSON(t, r, http.MethodPost, "/api/setup", "", map[string]any{
		"username": "admin", "password": "AdminPass123",
	}); code != http.StatusOK {
		t.Fatalf("setup: code=%d", code)
	}
	_, resp := doJSON(t, r, http.MethodPost, "/api/login", "", map[string]any{
		"username": "admin", "password": "AdminPass123",
	})
	adminTok, _ := resp["token"].(string)
	for _, u := range []struct{ name, pw string }{{"bob", "BobPass123456"}, {"carol", "CarolPass12345"}} {
		code, _ := doJSON(t, r, http.MethodPost, "/api/users", adminTok, map[string]any{
			"username": u.name, "password": u.pw, "email": u.name + "@example.com", "role": "user",
		})
		if code != http.StatusOK {
			t.Fatalf("create %s: code=%d", u.name, code)
		}
	}
	tokenOf := func(name, pw string) string {
		_, r := doJSON(t, r, http.MethodPost, "/api/login", "", map[string]any{"username": name, "password": pw})
		tok, _ := r["token"].(string)
		if tok == "" {
			t.Fatalf("login %s 未返回 token", name)
		}
		return tok
	}
	bobTok := tokenOf("bob", "BobPass123456")
	carolTok := tokenOf("carol", "CarolPass12345")

	// 前置：carol 的 legacy 接口应可用（200）。
	if code, _ := doJSON(t, r, http.MethodGet, "/api/vault/legacy", carolTok, nil); code != http.StatusOK {
		t.Fatalf("carol 初始 legacy 应为 200，实际 %d", code)
	}

	// bob 完成迁移（普通用户，非管理员）。
	if code, _ := doJSON(t, r, http.MethodPost, "/api/vault/legacy/done", bobTok, nil); code != http.StatusOK {
		t.Fatalf("bob 标记迁移完成应 200，实际 %d", code)
	}

	// bob 自己被封死。
	if code, _ := doJSON(t, r, http.MethodGet, "/api/vault/legacy", bobTok, nil); code != http.StatusGone {
		t.Fatalf("bob 迁移后应为 410，实际 %d", code)
	}
	// carol **不受影响**（这正是回归点）。
	if code, _ := doJSON(t, r, http.MethodGet, "/api/vault/legacy", carolTok, nil); code != http.StatusOK {
		t.Fatalf("carol 不应被 bob 的迁移影响，应为 200，实际 %d", code)
	}
	// admin 同样不受影响。
	if code, _ := doJSON(t, r, http.MethodGet, "/api/vault/legacy", adminTok, nil); code != http.StatusOK {
		t.Fatalf("admin 不应被 bob 的迁移影响，应为 200，实际 %d", code)
	}
}

// TestLegacyMarkerCompatWithGlobalKey 兼容性：早期版本写下的**全局**键
// `legacy_migration_done=1` 在升级后仍应被识别（只读兼容），避免已迁移用户
// 重新暴露 legacy 明文接口。
func TestLegacyMarkerCompatWithGlobalKey(t *testing.T) {
	r, database := newTestServer(t)
	if code, _ := doJSON(t, r, http.MethodPost, "/api/setup", "", map[string]any{
		"username": "admin", "password": "AdminPass123",
	}); code != http.StatusOK {
		t.Fatalf("setup: code=%d", code)
	}
	_, resp := doJSON(t, r, http.MethodPost, "/api/login", "", map[string]any{
		"username": "admin", "password": "AdminPass123",
	})
	tok, _ := resp["token"].(string)

	// 模拟旧版本遗留的全局标记。
	if err := db.SetMeta(database, "legacy_migration_done", "1"); err != nil {
		t.Fatalf("seed global marker: %v", err)
	}

	if code, _ := doJSON(t, r, http.MethodGet, "/api/vault/legacy", tok, nil); code != http.StatusGone {
		t.Fatalf("历史全局标记应仍被识别为已迁移（410），实际 %d", code)
	}
}

// TestRevisionNotControllableByClient 锁定 PT：服务端**绝不采纳**客户端提交的 revision。
//
// 若采纳客户端数值（取 max），持有旧副本的一方只需填入极大值即可：
//  ① 让陈旧数据在合并中"胜出"，覆盖服务端新数据（丢写）；
//  ② 把该条目 revision 永久抬高，压制其他设备的真实修改。
func TestRevisionNotControllableByClient(t *testing.T) {
	r, _ := newTestServer(t)
	if code, _ := doJSON(t, r, http.MethodPost, "/api/setup", "", map[string]any{
		"username": "admin", "password": "AdminPass123",
	}); code != http.StatusOK {
		t.Fatalf("setup: code=%d", code)
	}
	_, resp := doJSON(t, r, http.MethodPost, "/api/login", "", map[string]any{
		"username": "admin", "password": "AdminPass123",
	})
	tok, _ := resp["token"].(string)

	mkEntry := func(rev int64) map[string]any {
		return map[string]any{
			"id": 1, "uuid": "aaaaaaaa-0000-4000-8000-000000000001", "sort_order": 1,
			"title": "T", "username": "u", "password": "P", "url": "", "category": "", "notes": "",
			"created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
			"deleted": false, "revision": rev,
		}
	}
	getRev := func() float64 {
		_, d := doJSON(t, r, http.MethodGet, "/api/vault", tok, nil)
		entries, _ := d["entries"].([]any)
		if len(entries) == 0 {
			t.Fatal("vault 为空")
		}
		rev, _ := entries[0].(map[string]any)["revision"].(float64)
		return rev
	}

	if code, _ := doJSON(t, r, http.MethodPut, "/api/vault", tok, map[string]any{"entries": []any{mkEntry(0)}}); code != http.StatusOK {
		t.Fatalf("put #1: code=%d", code)
	}
	rev1 := getRev()

	// 客户端提交一个荒谬的大 revision。
	if code, _ := doJSON(t, r, http.MethodPut, "/api/vault", tok, map[string]any{"entries": []any{mkEntry(1_000_000_000)}}); code != http.StatusOK {
		t.Fatalf("put #2: code=%d", code)
	}
	rev2 := getRev()

	if rev2 >= 1_000_000_000 {
		t.Fatalf("客户端可控 revision：服务端采纳了客户端提交的 %v（禁止）", rev2)
	}
	if rev2 != rev1+1 {
		t.Fatalf("revision 应由服务端按 +1 推进：期望 %v，实际 %v", rev1+1, rev2)
	}
}
