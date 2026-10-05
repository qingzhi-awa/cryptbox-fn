package handlers

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/qingzhi-awa/cryptbox/shared/auth"
	"github.com/qingzhi-awa/cryptbox/shared/db"
)

// R6-02：GET /api/settings（admin-only）返回 SMTP 明文口令。
//
// 管理员会话一旦被 XSS / 令牌泄露等方式接管，攻击者即可直接读取 SMTP 授权码；
// 而该口令常与主邮箱同口令，危害外溢。导出接口（handleExportSettings）已按
// 既有约定掩码输出（auth.MaskedSecret），读取接口长期未对齐。
//
// 期望：普通读取应返回掩码（有口令时）或空串（无口令时），绝不返回明文。
func TestGetSettingsDoesNotLeakSMTPPassword(t *testing.T) {
	r, _, _ := newTestServerWithEncKey(t)
	if code, _ := doJSON(t, r, "POST", "/api/setup", "", gin.H{
		"username": "admin", "password": "AdminPass123",
	}); code != http.StatusOK {
		t.Fatalf("setup failed: %d", code)
	}
	tok := mustLogin(t, r, "admin", "AdminPass123")

	const secret = "SuperSecretAuthCode42"
	if code, resp := doJSON(t, r, "PUT", "/api/settings", tok, gin.H{
		"host": "smtp.qq.com", "port": 465, "username": "admin@qq.com",
		"password": secret, "from": "admin@qq.com", "ssl": true, "vendor": "qq",
	}); code != http.StatusOK {
		t.Fatalf("save settings failed: %d (%v)", code, resp)
	}

	code, body := doJSON(t, r, "GET", "/api/settings", tok, nil)
	if code != http.StatusOK {
		t.Fatalf("get settings failed: %d", code)
	}
	smtp, _ := body["smtp"].(map[string]any)
	if smtp == nil {
		t.Fatalf("响应缺少 smtp 字段：%v", body)
	}
	pw, _ := smtp["password"].(string)
	if pw == secret {
		t.Fatalf("GET /api/settings 泄露了 SMTP 明文口令：%q", pw)
	}
	if pw != auth.MaskedSecret {
		t.Fatalf("已配置口令时应返回掩码 %q，实际 %q", auth.MaskedSecret, pw)
	}
}

// 掩码回传保存必须保持原口令不变（不能被写成字面量 "******"）。
func TestGetSettingsMaskedPasswordKeepsOriginalOnSave(t *testing.T) {
	r, database, encKey := newTestServerWithEncKey(t)
	doJSON(t, r, "POST", "/api/setup", "", gin.H{
		"username": "admin", "password": "AdminPass123",
	})
	tok := mustLogin(t, r, "admin", "AdminPass123")

	const secret = "KeepMeAuthCode99"
	doJSON(t, r, "PUT", "/api/settings", tok, gin.H{
		"host": "smtp.qq.com", "port": 465, "username": "a@qq.com",
		"password": secret, "from": "a@qq.com", "ssl": true, "vendor": "qq",
	})

	// 模拟前端"原样回传"：把读取到的掩码再提交一次。
	_, body := doJSON(t, r, "GET", "/api/settings", tok, nil)
	smtp, _ := body["smtp"].(map[string]any)
	masked, _ := smtp["password"].(string)
	if code, _ := doJSON(t, r, "PUT", "/api/settings", tok, gin.H{
		"host": "smtp.qq.com", "port": 465, "username": "a@qq.com",
		"password": masked, "from": "a@qq.com", "ssl": true, "vendor": "qq",
	}); code != http.StatusOK {
		t.Fatalf("回传掩码保存失败：%d", code)
	}

	// 真实口令必须仍然完好：从库中取出密文并解密比对。
	stored := db.GetMeta(database, "smtp_password")
	if got := auth.DecryptSMTPPassword(encKey, stored); got != secret {
		t.Fatalf("掩码回传后口令被破坏：期望 %q，实际 %q", secret, got)
	}
}
