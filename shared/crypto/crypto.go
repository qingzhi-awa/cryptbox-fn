// Package crypto 提供 AES-256-GCM 对称加密与 scrypt 密钥派生。
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/scrypt"

	"github.com/qingzhi-awa/cryptbox/shared/db"
)

// scrypt 参数：N=32768, r=8, p=1，输出 32 字节密钥。
const (
	ScryptN      = 1 << 15 // 32768
	ScryptR      = 8
	ScryptP      = 1
	ScryptKeyLen = 32
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

// 服务端密钥文件名（位于数据目录，权限 0600）。
// PT-07：静态加密密钥与 JWT 签名密钥不再与业务数据同放一个 SQLite 文件——
// 数据库被拿走（备份、误提交、同机用户）即等于拿到"钥匙"，而钥匙本应与锁分离存放。
const (
	EncKeyFileName  = "server_enc.key"
	JWTKeyFileName  = "jwt.key"
	keyFilePermBits = 0o600
)

// LoadOrCreateBinaryKey 读取（必要时生成）二进制型密钥文件，返回原始字节。
//
// 顺序：文件已存在 → 直接使用；否则若 meta 中仍有旧值（base64）→ **原样迁移**到
// 文件并删除 meta（保证既有密文仍可解密）；否则生成新的随机密钥。
// 已存在的文件若权限过宽会被收紧为 0600。
func LoadOrCreateBinaryKey(database *sql.DB, path, metaKey string, size int) ([]byte, error) {
	if data, err := readKeyFile(path, size); err == nil {
		return data, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if legacy := db.GetMeta(database, metaKey); legacy != "" {
		data, err := base64.StdEncoding.DecodeString(legacy)
		if err != nil || len(data) != size {
			return nil, errors.New("meta 中的 " + metaKey + " 无法解析，拒绝以不安全状态启动")
		}
		if err := writeKeyFile(path, data); err != nil {
			return nil, err
		}
		if err := db.DeleteMeta(database, metaKey); err != nil {
			return nil, err
		}
		log.Printf("[crypto] 已将 %s 从数据库迁移到独立密钥文件 %s（数据库不再持有该密钥）", metaKey, path)
		return data, nil
	}
	key := make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := writeKeyFile(path, key); err != nil {
		return nil, err
	}
	return key, nil
}

// LoadOrCreateStringSecret 读取（必要时生成）字符串型密钥文件。
//
// 与二进制版本的区别：以**字符串原样**存取（而不做 base64 解码），这样从 meta
// 迁移过来的 JWT 签名密钥与迁移前的字节完全一致——否则升级瞬间会让所有已签发的
// 令牌立即失效。
func LoadOrCreateStringSecret(database *sql.DB, path, metaKey string, size int) (string, error) {
	if data, err := os.ReadFile(path); err == nil {
		s := strings.TrimSpace(string(data))
		if s == "" {
			return "", errors.New("密钥文件为空: " + path)
		}
		hardenKeyFile(path)
		return s, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if legacy := db.GetMeta(database, metaKey); legacy != "" {
		if err := writeKeyFile(path, []byte(legacy)); err != nil {
			return "", err
		}
		if err := db.DeleteMeta(database, metaKey); err != nil {
			return "", err
		}
		log.Printf("[crypto] 已将 %s 从数据库迁移到独立密钥文件 %s（既有令牌继续有效）", metaKey, path)
		return legacy, nil
	}
	key := make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	s := base64.StdEncoding.EncodeToString(key)
	if err := writeKeyFile(path, []byte(s)); err != nil {
		return "", err
	}
	return s, nil
}

// GetOrCreateEncryptionKey 读取或生成服务端静态加密密钥（数据目录下的独立文件）。
func GetOrCreateEncryptionKey(database *sql.DB, dataDir string) ([]byte, error) {
	return LoadOrCreateBinaryKey(database, filepath.Join(dataDir, EncKeyFileName), "encryption_key", 32)
}

// GetOrCreateJWTSecret 读取或生成 JWT 签名密钥（数据目录下的独立文件）。
// 避免使用硬编码默认密钥导致 token 可被伪造。
func GetOrCreateJWTSecret(database *sql.DB, dataDir string) (string, error) {
	return LoadOrCreateStringSecret(database, filepath.Join(dataDir, JWTKeyFileName), "jwt_secret", 32)
}

func readKeyFile(path string, size int) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) != size {
		return nil, errors.New("密钥文件长度异常: " + path)
	}
	hardenKeyFile(path)
	return data, nil
}

// writeKeyFile 写入密钥文件：目录 0700、文件 0600（Unix）。
func writeKeyFile(path string, data []byte) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, keyFilePermBits)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// hardenKeyFile 在 Unix 上把已存在但权限过宽的密钥文件收紧为 0600。
// Windows 无 POSIX 权限语义，由安装目录 ACL 保护（见 PT-14 说明）。
func hardenKeyFile(path string) {
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(path, keyFilePermBits); err != nil {
			log.Printf("[crypto] 警告：无法收紧密钥文件权限 %s: %v", path, err)
			return
		}
		log.Printf("[crypto] 已将密钥文件权限收紧为 0600: %s", path)
	}
}
