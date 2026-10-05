package handlers

import (
	"database/sql"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/qingzhi-awa/cryptbox/shared/auth"
	"github.com/qingzhi-awa/cryptbox/shared/config"
	"github.com/qingzhi-awa/cryptbox/shared/db"
)

// newTestServerWithEncKey 与 newTestServer 相同，但注入真实的服务端加密密钥，
// 用于覆盖 SMTP 口令加密/解密路径（nil 密钥时 EncryptSMTPPassword 会拒绝）。
func newTestServerWithEncKey(t *testing.T) (*gin.Engine, *sql.DB, []byte) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	dir := t.TempDir()
	cfg := config.Config{
		JWTSecret: "unit-test-jwt-secret",
		DBDSN:     filepath.Join(dir, "test.db"),
	}
	database, err := db.Open(cfg)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() {
		database.Close()
		_ = os.RemoveAll(dir)
	})
	encKey := []byte("0123456789abcdef0123456789abcdef") // AES-256 测试密钥
	r := gin.New()
	RegisterRoutes(r, cfg, database, encKey)
	return r, database, encKey
}

// TestImportSettingsEncryptsSMTPPassword 锁定 S-03：导入系统配置时 SMTP 口令必须
// 加密后落库，且能正确解密还原。
//
// 回归背景：handleUpdateSettings 会调用 auth.EncryptSMTPPassword 再落库（PT-07），
// 但 handleImportSettings 直接 SetMeta，明文口令会被写进 meta 表，破坏既定的密钥治理。
func TestImportSettingsEncryptsSMTPPassword(t *testing.T) {
	r, database, encKey := newTestServerWithEncKey(t)
	token := setupAdmin(t, r)

	const plain = "SuperSecretSmtpPw!"

	code, resp := doJSON(t, r, http.MethodPost, "/api/settings/import", token, map[string]any{
		"meta": map[string]any{"smtp_password": plain},
	})
	if code != http.StatusOK {
		t.Fatalf("导入配置: code=%d resp=%v", code, resp)
	}

	stored := db.GetMeta(database, "smtp_password")
	if stored == "" {
		t.Fatalf("smtp_password 未写入")
	}
	if stored == plain {
		t.Fatalf("smtp_password 以明文落库（应加密）")
	}
	if !strings.HasPrefix(stored, "enc:") {
		t.Fatalf("smtp_password 未带加密前缀，实际 %q", stored)
	}
	if strings.Contains(stored, plain) {
		t.Fatalf("密文中仍含明文口令")
	}

	// 反向确认：服务端能解密还原，保证功能未被破坏。
	cfg := auth.LoadSMTPConfig(database, encKey)
	if cfg.Password != plain {
		t.Fatalf("解密口令 = %q, 期望 %q", cfg.Password, plain)
	}
}

// TestImportSettingsMaskedPasswordPreservesExisting 确认导入掩码值时保持原口令不变。
func TestImportSettingsMaskedPasswordPreservesExisting(t *testing.T) {
	r, database, _ := newTestServerWithEncKey(t)
	token := setupAdmin(t, r)

	// 先经正常路径写入一个加密口令。
	code, _ := doJSON(t, r, http.MethodPut, "/api/settings", token, map[string]any{
		"host": "smtp.example.com", "port": 465, "username": "noreply@example.com",
		"from": "noreply@example.com", "password": "OriginalPw!",
	})
	if code != http.StatusOK {
		t.Fatalf("保存设置: code=%d", code)
	}
	before := db.GetMeta(database, "smtp_password")
	if before == "" {
		t.Fatalf("前置条件失败：smtp_password 未写入")
	}

	// 再导入掩码值，应保持原值。
	code, _ = doJSON(t, r, http.MethodPost, "/api/settings/import", token, map[string]any{
		"meta": map[string]any{"smtp_password": auth.MaskedSecret},
	})
	if code != http.StatusOK {
		t.Fatalf("导入掩码: code=%d", code)
	}
	if after := db.GetMeta(database, "smtp_password"); after != before {
		t.Fatalf("导入掩码后口令被改写：before=%q after=%q", before, after)
	}
}
