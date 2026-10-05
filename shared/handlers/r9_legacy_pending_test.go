package handlers

import (
	"net/http"
	"testing"

	"github.com/qingzhi-awa/cryptbox/shared/crypto"
)

// R9-03 回归测试：管理侧"未迁移账号"提示接口 GET /api/legacy-pending。
//
// 背景：legacy 明文迁移接口（GET /api/vault/legacy）是过渡期后门，计划在
// legacyAPIRemoveVersion 移除。对"升级后始终未迁移"的账号，其历史条目会持续以
// 服务端可解密的格式存在；本接口让管理员能定位这些账号并督促迁移。
//
// 覆盖：
//  1) 未迁移且存在服务端可解密条目的账号 → 出现在清单，且返回计划移除版本；
//  2) 只含端到端密文（服务端不可解）的账号 → 不出现；
//  3) 落"迁移完成"标记后 → 从清单消失。
func TestR9LegacyPendingListsUnmigratedAccounts(t *testing.T) {
	r, database, encKey := newTestServerWithEncKey(t)

	if c, _ := doJSON(t, r, http.MethodPost, "/api/setup", "", map[string]any{
		"username": "sa", "password": "SuperAdmin123",
	}); c != http.StatusOK {
		t.Fatalf("setup 超管失败: %d", c)
	}
	saTok := mustLogin(t, r, "sa", "SuperAdmin123")

	for _, name := range []string{"legacyuser", "modernuser"} {
		if c, resp := doJSON(t, r, http.MethodPost, "/api/users", saTok, map[string]any{
			"username": name, "password": "Passw0rd1", "email": name + "@mail.example", "role": "user",
		}); c != http.StatusOK {
			t.Fatalf("创建 %s 失败: %d %v", name, c, resp["error"])
		}
	}
	legacyID := r9UserID(t, r, saTok, "legacyuser")
	modernID := r9UserID(t, r, saTok, "modernuser")

	// legacyuser：一条服务端静态密钥可解密的旧条目。
	legacyEnc, err := crypto.AESEncryptString(encKey, "legacy-secret")
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO entries
		(id, uuid, sort_order, user_id, title, username, url, category, password_enc, notes_enc, created_at, updated_at, deleted, pinned, revision)
		VALUES (1, '', 0, ?, 'old', '', '', '', ?, '', '2026-01-01', '2026-01-01', 0, 0, 0)`,
		legacyID, legacyEnc); err != nil {
		t.Fatalf("插入 legacy 条目失败: %v", err)
	}
	// modernuser：一条端到端密文（非服务端密钥可解，模拟已迁移/新建）。
	if _, err := database.Exec(`INSERT INTO entries
		(id, uuid, sort_order, user_id, title, username, url, category, password_enc, notes_enc, created_at, updated_at, deleted, pinned, revision)
		VALUES (1, '', 0, ?, 'new', '', '', '', 'not-server-decryptable', '', '2026-01-01', '2026-01-01', 0, 0, 0)`,
		modernID); err != nil {
		t.Fatalf("插入 modern 条目失败: %v", err)
	}

	// —— 1) 初次查询：只有 legacyuser 在清单 ——
	c, resp := doJSON(t, r, http.MethodGet, "/api/legacy-pending", saTok, nil)
	if c != http.StatusOK {
		t.Fatalf("查询 legacy-pending 失败: %d %v", c, resp["error"])
	}
	if resp["remove_version"] != legacyAPIRemoveVersion {
		t.Errorf("remove_version=%v，期望 %q", resp["remove_version"], legacyAPIRemoveVersion)
	}
	if got := r9PendingHas(t, resp, "legacyuser"); !got {
		t.Errorf("legacyuser 未出现在未迁移清单")
	}
	if got := r9PendingHas(t, resp, "modernuser"); got {
		t.Errorf("modernuser（仅端到端密文）不应出现在未迁移清单")
	}
	if int(resp["count"].(float64)) != 1 {
		t.Errorf("count=%v，期望 1", resp["count"])
	}

	// —— 3) legacyuser 落迁移完成标记后应从清单消失 ——
	userTok := mustLogin(t, r, "legacyuser", "Passw0rd1")
	if c, resp := doJSON(t, r, http.MethodPost, "/api/vault/legacy/done", userTok, nil); c != http.StatusOK {
		t.Fatalf("上报迁移完成失败: %d %v", c, resp["error"])
	}
	c, resp = doJSON(t, r, http.MethodGet, "/api/legacy-pending", saTok, nil)
	if c != http.StatusOK {
		t.Fatalf("二次查询失败: %d", c)
	}
	if got := r9PendingHas(t, resp, "legacyuser"); got {
		t.Errorf("legacyuser 已上报迁移完成，仍出现在未迁移清单")
	}
	if int(resp["count"].(float64)) != 0 {
		t.Errorf("迁移完成后 count=%v，期望 0", resp["count"])
	}
}

// r9PendingHas 判断未迁移清单响应中是否含指定用户名。
func r9PendingHas(t *testing.T, resp map[string]any, name string) bool {
	t.Helper()
	users, _ := resp["users"].([]any)
	for _, u := range users {
		if m, ok := u.(map[string]any); ok && m["username"] == name {
			return true
		}
	}
	return false
}
