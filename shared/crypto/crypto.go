// Package crypto 提供 AES-256-GCM 对称加密与 scrypt 密钥派生。
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/scrypt"

	"github.com/qingzhi-awa/cryptbox/shared/db"
)

// scrypt 参数：N=32768, r=8, p=1，输出 32 字节密钥。
const (
	ScryptN      = 1 << 15 // 32768
	ScryptR       = 8
	ScryptP       = 1
	ScryptKeyLen  = 32
)

// ScryptDerive 使用 scrypt 从密码与盐派生密钥（N=32768, r=8, p=1, len=32）。
func ScryptDerive(password, salt []byte) ([]byte, error) {
	return scrypt.Key(password, salt, ScryptN, ScryptR, ScryptP, ScryptKeyLen)
}

// AESEncrypt 使用 AES-256-GCM 加密，返回 nonce+ciphertext 的 base64。
func AESEncrypt(key, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

// AESDecrypt 使用 AES-256-GCM 解密 base64 编码的 nonce+ciphertext。
func AESDecrypt(key []byte, encoded string) ([]byte, error) {
	ct, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ct) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := ct[:gcm.NonceSize()], ct[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}

// AESEncryptString 加密字符串。
func AESEncryptString(key []byte, s string) (string, error) {
	return AESEncrypt(key, []byte(s))
}

// AESDecryptString 解密字符串。
func AESDecryptString(key []byte, encoded string) (string, error) {
	b, err := AESDecrypt(key, encoded)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// GetOrCreateEncryptionKey 读取或生成服务端静态加密密钥（持久化在 meta 表）。
func GetOrCreateEncryptionKey(database *sql.DB) ([]byte, error) {
	keyB64 := db.GetMeta(database, "encryption_key")
	if keyB64 != "" {
		return base64.StdEncoding.DecodeString(keyB64)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := db.SetMeta(database, "encryption_key", base64.StdEncoding.EncodeToString(key)); err != nil {
		return nil, err
	}
	return key, nil
}
