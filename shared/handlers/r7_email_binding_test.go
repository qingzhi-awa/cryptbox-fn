package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"
)

// sha256Hex 复刻 auth 包私有的 hashCode 摘要格式（email + \x00 + purpose + \x00 + code），
// 便于直接向 email_verifications 表插入「已发码」状态。
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func verificationDigest(email, purpose, code string) string {
	return sha256Hex(email + "\x00" + purpose + "\x00" + code)
}

// R7-01 回归测试（第七轮修复）：
// 邮箱必须唯一，且自助改绑邮箱必须提供发送到「新邮箱」的所有权验证码。
//
// 覆盖：
//  1) 改绑到他人已占用的邮箱 → 唯一性拒绝（先于发码）；
//  2) 改绑到新邮箱：无验证码 → 拒绝；带正确验证码 → 成功；
//  3) 登录消歧：用户名与邮箱两条路径均可正常登录；
//  4) 口令重置不再跨账号串扰（原 UPDATE ... WHERE email 缺陷）。
func TestR7EmailBindingRegression(t *testing.T) {
	r, database := newTestServer(t)

	code, _ := doJSON(t, r, http.MethodPost, "/api/setup", "", map[string]any{
		"username": "admin", "password": "AdminPass123",
	})
	if code != http.StatusOK {
		t.Fatalf("setup 超管失败: %d", code)
	}
	// 开放注册 + 配置 SMTP（AllowRegistration 需要 SMTPConfigured）。
	if _, err := database.Exec(`INSERT OR REPLACE INTO meta (key, value) VALUES
		('allow_registration','true'), ('smtp_host','127.0.0.1'), ('smtp_port','25'),
		('smtp_enabled','true')`); err != nil {
		t.Fatalf("配置注册: %v", err)
	}
	register := func(username, email, codev, pass string) {
		if _, err := database.Exec(`INSERT INTO email_verifications (email, code, purpose, attempts, expires_at)
			VALUES (?, ?, 'register', 0, '9999999999')`,
			email, verificationDigest(email, "register", codev)); err != nil {
			t.Fatalf("插入验证码(%s): %v", username, err)
		}
		c, resp := doJSON(t, r, http.MethodPost, "/api/register", "", map[string]any{
			"username": username, "password": pass, "email": email, "code": codev,
		})
		if c != http.StatusOK {
			t.Fatalf("注册 %s 失败: %d %v", username, c, resp["error"])
		}
	}
	register("attacker", "attacker@evil.example", "111111", "Attacker99")
	register("victim", "victim@mail.example", "222222", "Passw0rd1")

	// 邮箱唯一索引应已在迁移中建立。
	var idxCount int
	if err := database.QueryRow(`SELECT COUNT(1) FROM sqlite_master WHERE type='index' AND name='idx_users_email_unique'`).Scan(&idxCount); err != nil {
		t.Fatalf("查询索引: %v", err)
	}
	if idxCount != 1 {
		t.Errorf("users.email 唯一索引未建立")
	}

	_, attackerResp := doJSON(t, r, http.MethodPost, "/api/login", "", map[string]any{
		"username": "attacker", "password": "Attacker99",
	})
	attackerToken := attackerResp["token"].(string)

	// —— 1) 改绑到他人已占用的邮箱：唯一性拒绝 ——
	code, resp := doJSON(t, r, http.MethodPut, "/api/me", attackerToken, map[string]any{
		"email": "victim@mail.example", "current_password": "Attacker99",
	})
	if code == http.StatusOK {
		t.Fatalf("改绑他人邮箱竟然成功：唯一性约束失效")
	}
	if code != http.StatusBadRequest && code != http.StatusConflict {
		t.Errorf("改绑他人邮箱应返回 400/409，实际 %d", code)
	}
	// 向他人邮箱发送绑定验证码应被拒（该邮箱已被占用）。
	code, resp = doJSON(t, r, http.MethodPost, "/api/me/email-code", attackerToken, map[string]any{
		"email": "victim@mail.example",
	})
	if code != http.StatusConflict {
		t.Errorf("向已被占用的邮箱发码应 409，实际 %d %v", code, resp["error"])
	}

	// —— 2) 改绑到自己的新邮箱：无验证码拒绝，带验证码成功 ——
	newEmail := "attacker2@evil.example"
	code, resp = doJSON(t, r, http.MethodPut, "/api/me", attackerToken, map[string]any{
		"email": newEmail, "current_password": "Attacker99",
	})
	if code != http.StatusBadRequest {
		t.Errorf("无验证码改绑应被拒（400），实际 %d %v", code, resp["error"])
	}
	// 模拟已收到新邮箱验证码。
	if _, err := database.Exec(`INSERT INTO email_verifications (email, code, purpose, attempts, expires_at)
		VALUES (?, ?, 'bind_email', 0, '9999999999')`,
		newEmail, verificationDigest(newEmail, "bind_email", "444444")); err != nil {
		t.Fatalf("插入绑定验证码: %v", err)
	}
	code, resp = doJSON(t, r, http.MethodPut, "/api/me", attackerToken, map[string]any{
		"email": newEmail, "email_code": "444444", "current_password": "Attacker99",
	})
	if code != http.StatusOK {
		t.Errorf("带正确验证码改绑应成功，实际 %d %v", code, resp["error"])
	}

	// —— 3) 登录消歧：邮箱登录、用户名登录均可 ——
	code, _ = doJSON(t, r, http.MethodPost, "/api/login", "", map[string]any{
		"username": "victim@mail.example", "password": "Passw0rd1",
	})
	if code != http.StatusOK {
		t.Errorf("受害者用邮箱登录失败（应成功）: %d", code)
	}
	code, _ = doJSON(t, r, http.MethodPost, "/api/login", "", map[string]any{
		"username": "victim", "password": "Passw0rd1",
	})
	if code != http.StatusOK {
		t.Errorf("受害者用用户名登录失败: %d", code)
	}

	// —— 4) 重置口令不跨账号串扰 ——
	const newPass = "VictimNew99"
	if _, err := database.Exec(`INSERT INTO email_verifications (email, code, purpose, attempts, expires_at)
		VALUES (?, ?, 'reset', 0, '9999999999')`,
		"victim@mail.example", verificationDigest("victim@mail.example", "reset", "333333")); err != nil {
		t.Fatalf("插入重置验证码: %v", err)
	}
	code, resp = doJSON(t, r, http.MethodPost, "/api/reset", "", map[string]any{
		"email": "victim@mail.example", "code": "333333", "password": newPass,
	})
	if code != http.StatusOK {
		t.Fatalf("重置失败: %d %v", code, resp["error"])
	}
	// attacker 的邮箱已改为 newEmail，其口令不应被 victim 的重置连带修改。
	code, _ = doJSON(t, r, http.MethodPost, "/api/login", "", map[string]any{
		"username": "attacker", "password": "Attacker99",
	})
	if code != http.StatusOK {
		t.Errorf("重置串扰回归：attacker 原口令失效（应仍可登录）: %d", code)
	}
	// 若 attacker 仍占用 victim 邮箱（缺陷场景），其口令会被连带改成 newPass。
	code, _ = doJSON(t, r, http.MethodPost, "/api/login", "", map[string]any{
		"username": "attacker", "password": newPass,
	})
	if code == http.StatusOK {
		t.Errorf("重置串扰回归：attacker 口令被 victim 的重置连带修改")
	}
}
