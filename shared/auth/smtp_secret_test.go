package auth

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/qingzhi-awa/cryptbox/shared/config"
	"github.com/qingzhi-awa/cryptbox/shared/db"
)

// TestSMTPPasswordEncryption 验证 PT-07：
//   - 口令以 enc: 前缀密文落库，库内不出现明文；
//   - 读取可正确还原；
//   - 历史明文（无前缀）仍可读取，且迁移后变为密文；
//   - 迁移幂等。
func TestSMTPPasswordEncryption(t *testing.T) {
	dir := t.TempDir()
	database, err := db.Open(config.Config{DBDSN: filepath.Join(dir, "t.db")})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer database.Close()

	encKey := []byte("0123456789abcdef0123456789abcdef")
	const plain = "smtp-auth-code-42"

	// 1) 加密写入。
	enc, err := EncryptSMTPPassword(encKey, plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !strings.HasPrefix(enc, "enc:") {
		t.Fatalf("密文应带 enc: 前缀，实际 %q", enc)
	}
	if strings.Contains(enc, plain) {
		t.Fatal("密文不应包含明文口令")
	}
	if err := db.SetMeta(database, "smtp_password", enc); err != nil {
		t.Fatalf("set meta: %v", err)
	}
	if got := LoadSMTPConfig(database, encKey).Password; got != plain {
		t.Fatalf("读取口令应为明文，实际 %q", got)
	}

	// 2) 历史明文：可读，迁移后变密文且仍可读。
	if err := db.SetMeta(database, "smtp_password", plain); err != nil {
		t.Fatalf("seed plaintext: %v", err)
	}
	if got := LoadSMTPConfig(database, encKey).Password; got != plain {
		t.Fatalf("历史明文应兼容可读，实际 %q", got)
	}
	if err := MigrateSMTPPassword(database, encKey); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	stored := db.GetMeta(database, "smtp_password")
	if !strings.HasPrefix(stored, "enc:") {
		t.Fatalf("迁移后应为密文，实际 %q", stored)
	}
	if stored == plain {
		t.Fatal("迁移后库内不应是明文")
	}
	if got := LoadSMTPConfig(database, encKey).Password; got != plain {
		t.Fatalf("迁移后仍应可解密，实际 %q", got)
	}

	// 3) 迁移幂等：再次迁移不改变库内值。
	if err := MigrateSMTPPassword(database, encKey); err != nil {
		t.Fatalf("re-migrate: %v", err)
	}
	if again := db.GetMeta(database, "smtp_password"); again != stored {
		t.Fatalf("迁移应幂等：%q → %q", stored, again)
	}

	// 4) 无密钥时拒绝以明文保存。
	if _, err := EncryptSMTPPassword(nil, plain); err == nil {
		t.Fatal("缺少服务端密钥时应拒绝加密（避免退回明文）")
	}
	// 5) 错误密钥解密失败时返回空串而非 panic。
	wrong := []byte("ffffffffffffffffffffffffffffffff")
	if got := DecryptSMTPPassword(wrong, stored); got != "" {
		t.Fatalf("错误密钥应解密失败并返回空串，实际 %q", got)
	}
	// 6) 掩码常量固定（导入/导出协议依赖它）。
	if MaskedSecret == "" || MaskedSecret == plain {
		t.Fatalf("掩码值不合法: %q", MaskedSecret)
	}
}
