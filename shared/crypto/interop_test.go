package crypto

import (
	"encoding/base64"
	"testing"
)

// 跨语言加密互操作测试向量（PT-08 补充）。
//
// 背景：vault key 的包裹链路跨越 Go 与 Rust 两端 ——
//   · 服务端（Go）只做透明存取，不参与加解密；
//   · 客户端（Rust）用 master key 加密得到 `vault_key_enc` 后上传，
//     之后再用同一 master key 解密取回。
// 但"服务端也能读到的静态加密"（legacy 迁移路径，见 GetOrCreateEncryptionKey）
// 以及若干离线工具都复用同一套 AES-256-GCM + scrypt 参数。只要任一端把
// scrypt 参数（N/r/p/len）或密文布局（nonce 长度、拼接顺序）改动一点，
// 存量数据就会**静默解不开**。这里用一组固定盐 + 固定明文 + 固定 nonce 的
// 向量把两端钉死：Rust 侧对应测试 `crypto::tests::interop_vector_*`。
//
// 向量生成方式（可复现）：
//   password = "correct horse battery staple"
//   salt     = "cryptbox-interop-salt-v1"（直接取字符串字节，走 derive_master_key 路径）
//   scrypt   = N=2^15, r=8, p=1, len=32
//   明文     = "vault-key-interop-plaintext-32byte!"
//   nonce    = 0x10 0x11 ... 0x1b（12 字节，仅测试用固定值）
const (
	interopPassword  = "correct horse battery staple"
	interopSalt      = "cryptbox-interop-salt-v1"
	interopPlaintext = "vault-key-interop-plaintext-32byte!"
	// 由上述参数推导出的 master key（base64）。
	interopDerivedB64 = "nIcNTIXf358lpHn+3nGTOfRi3WKEYeko10yX8qb9rco="
	// base64(nonce || AES-256-GCM ciphertext)。
	interopCiphertextB64 = "EBESExQVFhcYGRobkXO7RO9YXB8Ih0kIiDSVwkTUWIJSaeilCT/IhYtC95QYRgKXY/cPl3C7/5GULLK6ogEP"
)

// TestInteropScryptVector 锁定 scrypt 派生结果：Rust 端用同一密码+盐必须得到同一密钥。
func TestInteropScryptVector(t *testing.T) {
	got, err := ScryptDerive([]byte(interopPassword), []byte(interopSalt))
	if err != nil {
		t.Fatalf("scrypt 派生失败: %v", err)
	}
	if b64 := base64.StdEncoding.EncodeToString(got); b64 != interopDerivedB64 {
		t.Fatalf("scrypt 派生结果与冻结向量不一致（可能改了 N/r/p/len）：\n got=%s\nwant=%s", b64, interopDerivedB64)
	}
}

// TestInteropAESVectorDecrypt 用冻结向量验证 Go 能解开 Rust/Go 约定的密文布局。
func TestInteropAESVectorDecrypt(t *testing.T) {
	key, err := base64.StdEncoding.DecodeString(interopDerivedB64)
	if err != nil {
		t.Fatalf("解码向量密钥失败: %v", err)
	}
	pt, err := AESDecrypt(key, interopCiphertextB64)
	if err != nil {
		t.Fatalf("解密冻结向量失败（密文布局可能被改动）: %v", err)
	}
	if string(pt) != interopPlaintext {
		t.Fatalf("明文不匹配：got=%q want=%q", pt, interopPlaintext)
	}
}

// TestInteropAESVectorRoundTrip 反向验证：用同一密钥加密后能自解，且密文能跨端解读。
func TestInteropAESVectorRoundTrip(t *testing.T) {
	key, _ := base64.StdEncoding.DecodeString(interopDerivedB64)
	enc, err := AESEncryptString(key, interopPlaintext)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}
	back, err := AESDecryptString(key, enc)
	if err != nil {
		t.Fatalf("自解密失败: %v", err)
	}
	if back != interopPlaintext {
		t.Fatalf("往返后明文不一致：%q", back)
	}
}
