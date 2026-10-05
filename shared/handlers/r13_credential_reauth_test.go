package handlers

import (
	"net/http"
	"testing"
)

// R13-02 回归测试：解锁材料（kdf_salt / vault_key_enc）的改写必须做当前口令再验证。
//
// 背景：handleUpdateMe 原先只在「改密 / 改名 / 改邮箱」时校验 current_password，
// 遗漏了 kdf_salt 与 vault_key_enc。持有泄露令牌的攻击者可在不知道口令的情况下把
// kdf_salt 改成任意值，使正确口令再也派生不出能解开 vault_key_enc 的主密钥——
// 密码库永久无法解锁，且「旧密码恢复」同样失效。handlePutVaultKey 更是只需令牌
// 即可覆盖 vault_key_enc，构成等价的不可逆破坏入口。
//
// 覆盖：
//  1. PUT /api/me 仅提交 kdf_salt：无口令 → 400；口令错 → 400；口令对 → 200 且落库；
//  2. PUT /api/me 仅提交 vault_key_enc：无口令 → 400；口令对 → 200 且落库；
//  3. PUT /api/vault-key 首次启用（服务端为空）→ 免口令 200；
//  4. PUT /api/vault-key 覆盖既有密文：无口令 → 400；口令错 → 400；口令对 → 200。
func TestR13VaultMaterialWritesRequirePassword(t *testing.T) {
	r, _ := newTestServer(t)

	if code, _ := doJSON(t, r, http.MethodPost, "/api/setup", "", map[string]any{
		"username": "admin", "password": "AdminPass123",
	}); code != http.StatusOK {
		t.Fatalf("setup 超管失败: %d", code)
	}
	_, loginResp := doJSON(t, r, http.MethodPost, "/api/login", "", map[string]any{
		"username": "admin", "password": "AdminPass123",
	})
	token, _ := loginResp["token"].(string)
	if token == "" {
		t.Fatal("登录未取得令牌")
	}

	// —— 1) 仅改派生盐：必须再验证口令 ——
	code, _ := doJSON(t, r, http.MethodPut, "/api/me", token, map[string]any{"kdf_salt": "SALT-NEW-1"})
	if code != http.StatusBadRequest {
		t.Errorf("无口令改 kdf_salt 应 400，实际 %d", code)
	}
	code, _ = doJSON(t, r, http.MethodPut, "/api/me", token, map[string]any{
		"kdf_salt": "SALT-NEW-1", "current_password": "WRONG-PASS",
	})
	if code != http.StatusBadRequest {
		t.Errorf("口令错改 kdf_salt 应 400，实际 %d", code)
	}
	code, _ = doJSON(t, r, http.MethodPut, "/api/me", token, map[string]any{
		"kdf_salt": "SALT-NEW-1", "current_password": "AdminPass123",
	})
	if code != http.StatusOK {
		t.Fatalf("口令正确改 kdf_salt 应 200，实际 %d", code)
	}
	_, meResp := doJSON(t, r, http.MethodGet, "/api/me", token, nil)
	if got, _ := meResp["kdf_salt"].(string); got != "SALT-NEW-1" {
		t.Errorf("kdf_salt 未落库：%q", got)
	}

	// —— 2) 仅改 vault_key_enc（经 /api/me）——
	code, _ = doJSON(t, r, http.MethodPut, "/api/me", token, map[string]any{"vault_key_enc": "ENC-BY-ME"})
	if code != http.StatusBadRequest {
		t.Errorf("无口令经 /api/me 改 vault_key_enc 应 400，实际 %d", code)
	}
	code, _ = doJSON(t, r, http.MethodPut, "/api/me", token, map[string]any{
		"vault_key_enc": "ENC-BY-ME", "current_password": "AdminPass123",
	})
	if code != http.StatusOK {
		t.Fatalf("口令正确经 /api/me 改 vault_key_enc 应 200，实际 %d", code)
	}

	// —— 3) 首次启用：服务端 vault_key_enc 已被上一步写入，先清空模拟"首次" ——
	// 直接 DELETE /api/vault 会同时清空条目并置空密文，这正是前端"清空重建"路径。
	if code, _ := doJSON(t, r, http.MethodDelete, "/api/vault", token, nil); code != http.StatusOK {
		t.Fatalf("delete vault 失败: %d", code)
	}
	code, _ = doJSON(t, r, http.MethodPut, "/api/vault-key", token, map[string]any{"vault_key_enc": "ENC-FIRST"})
	if code != http.StatusOK {
		t.Fatalf("首次启用（密文为空）免口令写入应 200，实际 %d", code)
	}

	// —— 4) 覆盖既有密文：必须再验证口令 ——
	code, _ = doJSON(t, r, http.MethodPut, "/api/vault-key", token, map[string]any{"vault_key_enc": "ENC-OVERWRITE"})
	if code != http.StatusBadRequest {
		t.Errorf("无口令覆盖既有 vault_key_enc 应 400，实际 %d", code)
	}
	code, _ = doJSON(t, r, http.MethodPut, "/api/vault-key", token, map[string]any{
		"vault_key_enc": "ENC-OVERWRITE", "current_password": "WRONG-PASS",
	})
	if code != http.StatusBadRequest {
		t.Errorf("口令错覆盖既有 vault_key_enc 应 400，实际 %d", code)
	}
	code, _ = doJSON(t, r, http.MethodPut, "/api/vault-key", token, map[string]any{
		"vault_key_enc": "ENC-OVERWRITE", "current_password": "AdminPass123",
	})
	if code != http.StatusOK {
		t.Fatalf("口令正确覆盖既有 vault_key_enc 应 200，实际 %d", code)
	}
	_, meResp = doJSON(t, r, http.MethodGet, "/api/me", token, nil)
	if got, _ := meResp["vault_key_enc"].(string); got != "ENC-OVERWRITE" {
		t.Errorf("vault_key_enc 未落库：%q", got)
	}
}

// R13-01 回归测试：自助改绑邮箱发码接口必须挂「来源 IP」维度限流。
//
// 背景：/api/me/email-code 原先只有「按收件地址 3 次/15 分」一维，登录用户可以
// 轮换收件地址无限发信，把服务器当邮件轰炸器（损耗发信配额与域名信誉，最终破坏
// 注册/找回密码邮件）。修复后与 /register/send-code、/reset/send-code 同桶
// （sendCodeIP，20 次/小时/IP）。
//
// 本用例不依赖真实 SMTP：限流中间件在处理器之前执行，未配置邮件服务时
// 前 20 次返回 400（未配置邮件服务），第 21 次起必须返回 429。
func TestR13EmailCodeRouteHasIPLimit(t *testing.T) {
	r, _ := newTestServer(t)

	if code, _ := doJSON(t, r, http.MethodPost, "/api/setup", "", map[string]any{
		"username": "admin", "password": "AdminPass123",
	}); code != http.StatusOK {
		t.Fatalf("setup 超管失败: %d", code)
	}
	_, loginResp := doJSON(t, r, http.MethodPost, "/api/login", "", map[string]any{
		"username": "admin", "password": "AdminPass123",
	})
	token, _ := loginResp["token"].(string)
	if token == "" {
		t.Fatal("登录未取得令牌")
	}

	const ipLimitPerHour = 20 // 与 sendCodeIPPerHour 保持一致
	codes := make([]int, 0, ipLimitPerHour+5)
	for i := 0; i < ipLimitPerHour+5; i++ {
		// 每轮换一个收件地址：只可能被「来源 IP」维度拦住——这正是本用例要验证的。
		code, _ := doJSON(t, r, http.MethodPost, "/api/me/email-code", token, map[string]any{
			"email": "target" + string(rune('a'+i%26)) + "@example.com",
		})
		codes = append(codes, code)
	}
	for i, c := range codes {
		if i < ipLimitPerHour && c == http.StatusTooManyRequests {
			t.Fatalf("第 %d 次即被限流，早于配额（%d）", i+1, ipLimitPerHour)
		}
		if i >= ipLimitPerHour && c != http.StatusTooManyRequests {
			t.Fatalf("第 %d 次应 429（IP 限流生效），实际 %d（完整序列 %v）", i+1, c, codes)
		}
	}
}
