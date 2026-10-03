package crypto

import (
	"database/sql"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/qingzhi-awa/cryptbox/shared/config"
	"github.com/qingzhi-awa/cryptbox/shared/db"
)

func tempDB(t *testing.T) *sql.DB {
	t.Helper()
	dir := t.TempDir()
	database, err := db.Open(config.Config{DBDSN: filepath.Join(dir, "t.db")})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	return database
}

// TestBinaryKeyFileCreateAndMigrate 验证 PT-07：
//   - 无旧值时生成新的 32 字节密钥文件（Unix 权限 0600）；
//   - meta 中有旧值时**原样迁移**（既有密文仍可解密）并删除 meta；
//   - 重复调用返回同一密钥（幂等）。
func TestBinaryKeyFileCreateAndMigrate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server_enc.key")

	// 1) 全新生成。
	database := tempDB(t)
	key1, err := LoadOrCreateBinaryKey(database, path, "encryption_key", 32)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(key1) != 32 {
		t.Fatalf("密钥长度应为 32，实际 %d", len(key1))
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("密钥文件应已生成: %v", err)
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(path)
		if info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("密钥文件权限应仅限本用户，实际 %o", info.Mode().Perm())
		}
	}
	// 幂等：再次调用得到同一密钥。
	if again, err := LoadOrCreateBinaryKey(database, path, "encryption_key", 32); err != nil || string(again) != string(key1) {
		t.Fatalf("重复调用应返回同一密钥: %v", err)
	}

	// 2) 模拟旧库：meta 中已有密钥（base64），文件不存在 → 必须原样迁移。
	dir2 := t.TempDir()
	path2 := filepath.Join(dir2, "server_enc.key")
	database2 := tempDB(t)
	legacy := make([]byte, 32)
	for i := range legacy {
		legacy[i] = byte(i + 1)
	}
	if err := db.SetMeta(database2, "encryption_key", base64.StdEncoding.EncodeToString(legacy)); err != nil {
		t.Fatalf("seed meta: %v", err)
	}
	got, err := LoadOrCreateBinaryKey(database2, path2, "encryption_key", 32)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if string(got) != string(legacy) {
		t.Fatal("迁移必须保留原密钥，否则既有密文将永久无法解密")
	}
	if v := db.GetMeta(database2, "encryption_key"); v != "" {
		t.Fatalf("迁移后应清除 meta 中的旧密钥，实际 %q", v)
	}
	onDisk, _ := os.ReadFile(path2)
	if string(onDisk) != string(legacy) {
		t.Fatal("密钥文件内容应与迁移前一致")
	}
}

// TestStringSecretFileMigratesVerbatim 验证 JWT 签名密钥迁移时**逐字节保留**：
// 若做了 base64 解码，签名密钥会改变，升级瞬间所有已签发令牌都会失效。
func TestStringSecretFileMigratesVerbatim(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jwt.key")
	database := tempDB(t)

	const legacy = "TGVnYWN5SldUU2VjcmV0S2V5MzJCeXRlc0Jhc2U2NCE="
	if err := db.SetMeta(database, "jwt_secret", legacy); err != nil {
		t.Fatalf("seed: %v", err)
	}
	got, err := LoadOrCreateStringSecret(database, path, "jwt_secret", 32)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if got != legacy {
		t.Fatalf("JWT 密钥必须逐字节保留，实际 %q", got)
	}
	if v := db.GetMeta(database, "jwt_secret"); v != "" {
		t.Fatalf("迁移后应清除 meta，实际 %q", v)
	}
	// 再次读取（走文件路径）仍是同一值。
	if again, err := LoadOrCreateStringSecret(database, path, "jwt_secret", 32); err != nil || again != legacy {
		t.Fatalf("二次读取应一致: %v", err)
	}
}

// TestKeyFilePermissionHardened 已存在但权限过宽的文件应被收紧（Unix）。
func TestKeyFilePermissionHardened(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 无 POSIX 权限语义，由目录 ACL 保护")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "server_enc.key")
	if err := os.WriteFile(path, make([]byte, 32), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	database := tempDB(t)
	if _, err := LoadOrCreateBinaryKey(database, path, "encryption_key", 32); err != nil {
		t.Fatalf("load: %v", err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("权限应被收紧为 0600，实际 %o", info.Mode().Perm())
	}
}

// TestKeyFileLengthGuard 长度异常的文件应报错而非静默生成新密钥。
func TestKeyFileLengthGuard(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.key")
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	database := tempDB(t)
	if _, err := LoadOrCreateBinaryKey(database, path, "encryption_key", 32); err == nil {
		t.Fatal("长度异常的密钥文件应返回错误")
	}
}
