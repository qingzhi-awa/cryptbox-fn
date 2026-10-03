package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/qingzhi-awa/cryptbox/shared/auth"
	"github.com/qingzhi-awa/cryptbox/shared/config"
	"github.com/qingzhi-awa/cryptbox/shared/crypto"
	"github.com/qingzhi-awa/cryptbox/shared/db"
)

// newTestServer 构建一个基于临时 SQLite 文件的完整路由测试环境。
func newTestServer(t *testing.T) (*gin.Engine, *sql.DB) {
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
	r := gin.New()
	RegisterRoutes(r, cfg, database, nil)
	return r, database
}

// doJSON 发起 JSON 请求并解析响应。
func doJSON(t *testing.T, r http.Handler, method, path string, token string, body any) (int, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// TestVaultRecoveryAfterPasswordReset 验证密码重置后的两条恢复路径：
//  1. 旧密码恢复：旧 master 解开 vault key → 新 master 重新包裹上传 → 条目明文无损；
//  2. 清空重建：DELETE /api/vault 后 vault_key_enc 置空、条目清空，可重新开始。
func TestVaultRecoveryAfterPasswordReset(t *testing.T) {
	r, database := newTestServer(t)

	const (
		oldPw  = "OldPass123"
		newPw  = "NewPass456"
		salt   = "dGVzdC1zYWx0LXRlc3Qtc2FsdA==" // base64("test-salt-test-salt")
		secret = "BankSecret!42"
		note   = "机密备注"
	)

	// 1) 初始化：用旧密码派生 master，加密随机 vault key，随 setup 上传（与前端/客户端同构）。
	masterOld, err := crypto.ScryptDerive([]byte(oldPw), []byte(salt))
	if err != nil {
		t.Fatalf("derive old master: %v", err)
	}
	vaultKeyEnc, err := crypto.AESEncrypt(masterOld, []byte("0123456789abcdef0123456789abcdef")) // 32 字节 vault key
	if err != nil {
		t.Fatalf("wrap vault key: %v", err)
	}
	code, resp := doJSON(t, r, http.MethodPost, "/api/setup", "", map[string]any{
		"username": "alice", "password": oldPw, "vault_key_enc": vaultKeyEnc, "kdf_salt": salt,
	})
	if code != http.StatusOK {
		t.Fatalf("setup: code=%d resp=%v", code, resp)
	}
	token, _ := resp["token"].(string)
	if token == "" {
		t.Fatal("setup 未返回 token")
	}

	// 2) 上传一条加密条目（password/notes 为 vault key 加密后的密文）。
	var vk [32]byte
	vkPlain, err := crypto.AESDecrypt(masterOld, vaultKeyEnc)
	if err != nil || len(vkPlain) != 32 {
		t.Fatalf("unwrap vault key: %v (len=%d)", err, len(vkPlain))
	}
	copy(vk[:], vkPlain)
	entryPw, err := crypto.AESEncrypt(vkPlain, []byte(secret))
	if err != nil {
		t.Fatalf("encrypt entry password: %v", err)
	}
	entryNote, err := crypto.AESEncrypt(vkPlain, []byte(note))
	if err != nil {
		t.Fatalf("encrypt entry notes: %v", err)
	}
	code, _ = doJSON(t, r, http.MethodPut, "/api/vault", token, map[string]any{
		"entries": []map[string]any{{
			"id": 1, "sort_order": 1, "title": "银行账户", "username": "alice-bank",
			"password": entryPw, "url": "https://bank.example.com", "category": "金融",
			"notes": entryNote, "created_at": "t0", "updated_at": "t0", "deleted": false,
		}},
	})
	if code != http.StatusOK {
		t.Fatalf("put vault: code=%d", code)
	}

	// 3) 模拟「忘记密码」：服务端直接把口令哈希换成新密码（等价于验证码重置结果）。
	newHash, err := auth.HashPassword(newPw)
	if err != nil {
		t.Fatalf("hash new pw: %v", err)
	}
	if _, err := database.Exec(`UPDATE users SET password_hash = ? WHERE username = 'alice'`, newHash); err != nil {
		t.Fatalf("reset password: %v", err)
	}

	// 4) 新密码登录成功，但新 master 解不开旧 vault_key_enc —— 复现问题本身。
	code, resp = doJSON(t, r, http.MethodPost, "/api/login", "", map[string]any{"username": "alice", "password": newPw})
	if code != http.StatusOK {
		t.Fatalf("login with new pw: code=%d", code)
	}
	newToken, _ := resp["token"].(string)
	encFromServer, _ := resp["vault_key_enc"].(string)
	if encFromServer == "" {
		t.Fatal("登录响应缺少 vault_key_enc")
	}
	if _, err := crypto.AESDecrypt(mustMaster(t, newPw, salt), encFromServer); err == nil {
		t.Fatal("预期新密码解不开旧 vault_key_enc，但解密成功了")
	}

	// 5) 路径一「旧密码恢复」：旧 master 解开 → 新 master 重新包裹 → 上传。
	vkPlain2, err := crypto.AESDecrypt(mustMaster(t, oldPw, salt), encFromServer)
	if err != nil || len(vkPlain2) != 32 {
		t.Fatalf("旧密码恢复：解开旧 vault key 失败: %v", err)
	}
	rewrapped, err := crypto.AESEncrypt(mustMaster(t, newPw, salt), vkPlain2)
	if err != nil {
		t.Fatalf("re-wrap: %v", err)
	}
	code, _ = doJSON(t, r, http.MethodPut, "/api/vault-key", newToken, map[string]any{"vault_key_enc": rewrapped})
	if code != http.StatusOK {
		t.Fatalf("put re-wrapped vault key: code=%d", code)
	}

	// 6) 数据无损验证：新 master 解开 vault key，条目明文与重置前完全一致。
	vkNow, err := crypto.AESDecrypt(mustMaster(t, newPw, salt), rewrapped)
	if err != nil {
		t.Fatalf("unwrap with new master: %v", err)
	}
	code, resp = doJSON(t, r, http.MethodGet, "/api/vault", newToken, nil)
	if code != http.StatusOK {
		t.Fatalf("get vault: code=%d", code)
	}
	entries, _ := resp["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("期望 1 条条目，实际 %d", len(entries))
	}
	e0 := entries[0].(map[string]any)
	plainPw, err := crypto.AESDecryptString(vkNow, e0["password"].(string))
	if err != nil || plainPw != secret {
		t.Fatalf("条目 password 明文不符: %q err=%v", plainPw, err)
	}
	plainNote, err := crypto.AESDecryptString(vkNow, e0["notes"].(string))
	if err != nil || plainNote != note {
		t.Fatalf("条目 notes 明文不符: %q err=%v", plainNote, err)
	}

	// 7) 路径二「清空重建」：DELETE /api/vault 后 vault_key_enc 置空、条目清空。
	code, _ = doJSON(t, r, http.MethodDelete, "/api/vault", newToken, nil)
	if code != http.StatusOK {
		t.Fatalf("delete vault: code=%d", code)
	}
	code, resp = doJSON(t, r, http.MethodGet, "/api/me", newToken, nil)
	if enc, _ := resp["vault_key_enc"].(string); code != http.StatusOK || enc != "" {
		t.Fatalf("清空后 vault_key_enc 应为空: code=%d enc=%q", code, enc)
	}
	code, resp = doJSON(t, r, http.MethodGet, "/api/vault", newToken, nil)
	if entries, _ := resp["entries"].([]any); code != http.StatusOK || len(entries) != 0 {
		t.Fatalf("清空后条目应为 0: code=%d n=%d", code, len(entries))
	}

	// 8) 清空后重新解锁：vault_key_enc 为空 → 前端生成新 vault key 并上传（既有逻辑），此处验证接口可用。
	freshEnc, err := crypto.AESEncrypt(mustMaster(t, newPw, salt), []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("wrap fresh vault key: %v", err)
	}
	code, _ = doJSON(t, r, http.MethodPut, "/api/vault-key", newToken, map[string]any{"vault_key_enc": freshEnc})
	if code != http.StatusOK {
		t.Fatalf("重新设置 vault key: code=%d", code)
	}
}

func mustMaster(t *testing.T, password, salt string) []byte {
	t.Helper()
	m, err := crypto.ScryptDerive([]byte(password), []byte(salt))
	if err != nil {
		t.Fatalf("derive master(%s): %v", password, err)
	}
	return m
}
