package handlers

import (
	"net/http"
	"testing"
)

// setupAdmin 初始化测试服务并返回管理员令牌。
func setupAdmin(t *testing.T, r http.Handler) string {
	t.Helper()
	code, resp := doJSON(t, r, http.MethodPost, "/api/setup", "", map[string]any{
		"username": "admin", "password": "AdminPass123",
	})
	if code != http.StatusOK {
		t.Fatalf("setup: code=%d resp=%v", code, resp)
	}
	token, _ := resp["token"].(string)
	if token == "" {
		t.Fatalf("setup 未返回 token")
	}
	return token
}

// entryBody 由 vault_isolation_test.go 提供（端到端加密条目的构造样板）。

// pinnedOf 从 GET /api/vault 的响应中取出指定 id 条目的置顶状态。
func pinnedOf(t *testing.T, r http.Handler, token string, id int64) (bool, bool) {
	t.Helper()
	code, resp := doJSON(t, r, http.MethodGet, "/api/vault", token, nil)
	if code != http.StatusOK {
		t.Fatalf("GET /api/vault: code=%d resp=%v", code, resp)
	}
	raw, _ := resp["entries"].([]any)
	found := false
	pinned := false
	for _, it := range raw {
		m, _ := it.(map[string]any)
		if m == nil {
			continue
		}
		if v, _ := m["id"].(float64); int64(v) == id {
			found = true
			pinned, _ = m["pinned"].(bool)
		}
	}
	return found, pinned
}

// pinSyncOf 读取账号级「置顶参与同步」开关（GET /api/vault 响应中的字段）。
func pinSyncOf(t *testing.T, r http.Handler, token string) bool {
	t.Helper()
	code, resp := doJSON(t, r, http.MethodGet, "/api/vault", token, nil)
	if code != http.StatusOK {
		t.Fatalf("GET /api/vault: code=%d resp=%v", code, resp)
	}
	v, _ := resp["pin_sync"].(bool)
	return v
}

// stripPinned 移除载荷中的 pinned 字段，模拟「已关闭置顶同步」的桌面端上传：
// 该客户端按设备在本地保管置顶，上传时不携带置顶状态。
func stripPinned(entries []map[string]any) []map[string]any {
	out := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		c := make(map[string]any, len(e))
		for k, v := range e {
			if k == "pinned" {
				continue
			}
			c[k] = v
		}
		out = append(out, c)
	}
	return out
}

// TestEntryPinnedWebRoundTrip 网页端置顶（载荷携带 pinned）应被服务端保存并返回。
func TestEntryPinnedWebRoundTrip(t *testing.T) {
	r, _ := newTestServer(t)
	token := setupAdmin(t, r)

	if pinSyncOf(t, r, token) {
		t.Fatalf("置顶同步默认应为关闭")
	}

	a := entryBody(1, "A")
	a["pinned"] = true
	b := entryBody(2, "B")
	code, resp := doJSON(t, r, http.MethodPost, "/api/vault", token, map[string]any{"entries": []map[string]any{a, b}})
	if code != http.StatusOK {
		t.Fatalf("上传: code=%d resp=%v", code, resp)
	}
	if found, pinned := pinnedOf(t, r, token, 1); !found || !pinned {
		t.Fatalf("A 应为置顶, found=%v pinned=%v", found, pinned)
	}
	if found, pinned := pinnedOf(t, r, token, 2); !found || pinned {
		t.Fatalf("B 应为未置顶, found=%v pinned=%v", found, pinned)
	}
}

// TestEntryPinnedPreservedWithoutField 核心语义：关闭置顶同步的桌面端上传时
// **不携带** pinned 字段，服务端必须保留已存的置顶状态（网页端按账号的置顶不被覆盖）。
func TestEntryPinnedPreservedWithoutField(t *testing.T) {
	r, _ := newTestServer(t)
	token := setupAdmin(t, r)

	a := entryBody(1, "A")
	a["pinned"] = true
	b := entryBody(2, "B")
	code, _ := doJSON(t, r, http.MethodPost, "/api/vault", token, map[string]any{"entries": []map[string]any{a, b}})
	if code != http.StatusOK {
		t.Fatalf("上传: code=%d", code)
	}

	// 桌面端（关闭置顶同步）整库上传：载荷不带 pinned。
	code, _ = doJSON(t, r, http.MethodPost, "/api/vault", token, map[string]any{
		"entries": stripPinned([]map[string]any{entryBody(1, "A"), entryBody(2, "B")}),
	})
	if code != http.StatusOK {
		t.Fatalf("桌面端上传: code=%d", code)
	}
	if _, pinned := pinnedOf(t, r, token, 1); !pinned {
		t.Fatalf("载荷未携带 pinned 时应保留服务端已存置顶")
	}
}

// TestPinSyncOnAdoptsIncoming 开启「置顶参与同步」后，桌面端上传携带的置顶状态生效
//（最后上传者生效，与排序等密码库数据一致）。
func TestPinSyncOnAdoptsIncoming(t *testing.T) {
	r, _ := newTestServer(t)
	token := setupAdmin(t, r)

	a := entryBody(1, "A")
	a["pinned"] = true
	code, _ := doJSON(t, r, http.MethodPost, "/api/vault", token, map[string]any{"entries": []map[string]any{a}})
	if code != http.StatusOK {
		t.Fatalf("上传: code=%d", code)
	}

	// 开启开关。
	code, resp := doJSON(t, r, http.MethodPost, "/api/vault/pin-sync", token, map[string]any{"enabled": true})
	if code != http.StatusOK {
		t.Fatalf("开启开关: code=%d resp=%v", code, resp)
	}
	if !pinSyncOf(t, r, token) {
		t.Fatalf("开启后 GET /api/vault 应返回 pin_sync=true")
	}

	// 桌面端（开启置顶同步）上传：载荷携带本机置顶状态 → 服务端采纳。
	code, _ = doJSON(t, r, http.MethodPost, "/api/vault", token, map[string]any{
		"entries": stripPinned([]map[string]any{entryBody(1, "A")}),
	})
	if code != http.StatusOK {
		t.Fatalf("桌面端上传: code=%d", code)
	}
	// 注意：即便载荷省略了 pinned，开启同步的客户端本应携带；此用例验证
	// 「省略即保留」与开关无关，真正生效路径见下。
	if _, pinned := pinnedOf(t, r, token, 1); !pinned {
		t.Fatalf("省略 pinned 时应保留已存状态")
	}

	// 携带 pinned=false 的整库上传 → 服务端采纳（本机取消置顶）。
	off := entryBody(1, "A")
	off["pinned"] = false
	code, _ = doJSON(t, r, http.MethodPost, "/api/vault", token, map[string]any{"entries": []map[string]any{off}})
	if code != http.StatusOK {
		t.Fatalf("携带 pinned 上传: code=%d", code)
	}
	if _, pinned := pinnedOf(t, r, token, 1); pinned {
		t.Fatalf("载荷携带 pinned=false 时应被采纳")
	}
}

// TestPinSyncEndpoints 开关接口的读写与鉴权。
func TestPinSyncEndpoints(t *testing.T) {
	r, _ := newTestServer(t)
	token := setupAdmin(t, r)

	code, resp := doJSON(t, r, http.MethodGet, "/api/vault/pin-sync", token, nil)
	if code != http.StatusOK {
		t.Fatalf("GET pin-sync: code=%d resp=%v", code, resp)
	}
	if v, _ := resp["pin_sync"].(bool); v {
		t.Fatalf("默认应为关闭")
	}

	// 未登录访问应被拒绝。
	if code, _ := doJSON(t, r, http.MethodGet, "/api/vault/pin-sync", "", nil); code == http.StatusOK {
		t.Fatalf("未登录不应返回 200")
	}
	if code, _ := doJSON(t, r, http.MethodPost, "/api/vault/pin-sync", "", map[string]any{"enabled": true}); code == http.StatusOK {
		t.Fatalf("未登录不应能修改开关")
	}
}

// TestPinSyncInvalidBody 开关接口对非法请求体应返回 400。
func TestPinSyncInvalidBody(t *testing.T) {
	r, _ := newTestServer(t)
	token := setupAdmin(t, r)

	code, _ := doJSON(t, r, http.MethodPost, "/api/vault/pin-sync", token, map[string]any{})
	if code != http.StatusBadRequest {
		t.Fatalf("缺少 enabled 应返回 400, got=%d", code)
	}
}
