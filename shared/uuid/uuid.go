// Package uuid 提供 RFC 4122 的 UUID v4（随机）与 v5（确定性）实现。
//
// 用途（PT-04）：条目同步标识改为全局唯一，避免「同一账号多设备各自按本地自增
// id 合并」导致不同条目互相覆盖、静默丢数据。
//   - 新条目：客户端/前端生成 v4（随机）→ 天然全局唯一；
//   - 存量条目：服务端按 (user_id, legacy_id) 派生 v5 → 各端对同一条目得到同一
//     标识，迁移幂等且无需用户干预。
//
// 本包刻意不引入第三方依赖：v4 只需 crypto/rand，v5 只需 SHA-1 + 固定命名空间。
package uuid

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
)

// Namespace 是本应用 UUIDv5 的命名空间。
//
// 该值一旦发布**不得更改**：存量条目的确定性标识由它与 (user_id, id) 共同决定，
// 更改会导致同一历史条目在不同版本上得到不同 uuid。
var Namespace = [16]byte{
	0x8f, 0x2a, 0x6c, 0x14, 0x5d, 0x3b, 0x4e, 0x79,
	0x9a, 0x01, 0xc7, 0xb6, 0xd8, 0xe4, 0xf2, 0x10,
}

// NewV4 生成随机 UUID（version 4）。
func NewV4() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand 失败意味着系统熵源不可用；此时不应静默降级为弱随机。
		panic("uuid: 随机源不可用: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant RFC 4122
	return format(b)
}

// NewV5 基于命名空间与名称生成确定性 UUID（version 5，SHA-1）。
func NewV5(ns [16]byte, name string) string {
	h := sha1.New()
	h.Write(ns[:])
	h.Write([]byte(name))
	sum := h.Sum(nil)
	var b [16]byte
	copy(b[:], sum[:16])
	b[6] = (b[6] & 0x0f) | 0x50 // version 5
	b[8] = (b[8] & 0x3f) | 0x80 // variant RFC 4122
	return format(b)
}

// Deterministic 返回某用户的某条存量条目在旧数据模型下的确定性标识。
//
// 名称格式 "userID:legacyID" 同时包含用户与本地自增 id，因此：
//   - 不同用户互相隔离；
//   - 同一用户在不同端（若 id 一致，例如数据本来自服务端）得到相同 uuid。
func Deterministic(userID, legacyID int64) string {
	return NewV5(Namespace, fmt.Sprintf("%d:%d", userID, legacyID))
}

// IsValid 粗略校验字符串是否为标准 8-4-4-4-12 十六进制 UUID。
func IsValid(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	}
	return true
}

func format(b [16]byte) string {
	var buf [36]byte
	hex.Encode(buf[0:8], b[0:4])
	buf[8] = '-'
	hex.Encode(buf[9:13], b[4:6])
	buf[13] = '-'
	hex.Encode(buf[14:18], b[6:8])
	buf[18] = '-'
	hex.Encode(buf[19:23], b[8:10])
	buf[23] = '-'
	hex.Encode(buf[24:36], b[10:16])
	return string(buf[:])
}
