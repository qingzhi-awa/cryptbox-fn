package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qingzhi-awa/cryptbox/shared/config"
	"github.com/qingzhi-awa/cryptbox/shared/crypto"
	"github.com/qingzhi-awa/cryptbox/shared/db"
)

// TestSetupSMTPFromInstallEncryptsAtWrite 验证 R7-02：安装向导写入的 SMTP 口令
// 在写入口即被加密（enc: 前缀），不再有「明文已落库、尚未迁移」的窗口。
func TestSetupSMTPFromInstallEncryptsAtWrite(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{DBDSN: filepath.Join(dir, "app.db")}
	database, err := db.Open(cfg)
	if err != nil {
		t.Fatalf("打开数据库: %v", err)
	}
	defer database.Close()

	// 模拟安装向导产物：host/port/username/password/ssl/vendor
	conf := "smtp.qq.com\n465\nme@qq.com\nSecretAuthCode\ntrue\nqq\n"
	if err := os.WriteFile(filepath.Join(dir, "smtp.conf"), []byte(conf), 0o600); err != nil {
		t.Fatalf("写入 smtp.conf: %v", err)
	}

	encKey, err := crypto.GetOrCreateEncryptionKey(database, dir)
	if err != nil {
		t.Fatalf("生成加密密钥: %v", err)
	}
	if err := setupSMTPFromInstall(database, cfg, encKey); err != nil {
		t.Fatalf("setupSMTPFromInstall: %v", err)
	}

	stored := db.GetMeta(database, "smtp_password")
	if stored == "SecretAuthCode" {
		t.Errorf("SMTP 口令以明文落库（R7-02 未修复）")
	}
	if !strings.HasPrefix(stored, "enc:") {
		t.Errorf("SMTP 口令应为 enc: 前缀密文，实际: %q", stored)
	}
}
