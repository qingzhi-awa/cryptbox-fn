package auth

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// b64url 是 JWT 各段使用的 base64url（无填充）编码。
func b64url(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}

// craftToken 用指定 alg 头手工拼一个 token，绕过 GenerateToken 以模拟攻击者/异端签发端。
func craftToken(t *testing.T, header map[string]any, claims Claims) string {
	t.Helper()
	hb, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	return b64url(hb) + "." + b64url(cb) + "."
}

// TestParseTokenRejectsAlgNone 锁定 VULN F：解析端必须固定算法，拒收 alg=none 的令牌。
//
// 回归背景：ParseToken 早期只提供 keyFunc、未限定算法。虽然 golang-jwt/v5 已默认拒绝
// none，但"不限定算法"属纵深防御缺口；一旦将来引入非对称密钥，未固定算法就可能被
// 诱导走错误校验分支。修复后显式 jwt.WithValidMethods(["HS256"])。
func TestParseTokenRejectsAlgNone(t *testing.T) {
	const secret = "unit-test-secret"
	tok := craftToken(t, map[string]any{"alg": "none", "typ": "JWT"}, Claims{
		UserID:   1,
		Username: "admin",
		Role:     "superadmin",
		TokenVer: 0,
	})
	if _, err := ParseToken(secret, tok); err == nil {
		t.Fatalf("alg=none 令牌必须被拒绝")
	}
}

// TestParseTokenRejectsHS384 锁定算法固定的另一面：即便签名算法同族（HMAC），
// 非 HS256 也必须拒绝，避免"接受任何 HMAC 变体"的隐式放宽。
func TestParseTokenRejectsHS384(t *testing.T) {
	const secret = "unit-test-secret"
	claims := Claims{UserID: 1, Username: "admin", Role: "superadmin"}
	hb, _ := json.Marshal(map[string]any{"alg": "HS384", "typ": "JWT"})
	cb, _ := json.Marshal(claims)
	signing := b64url(hb) + "." + b64url(cb)
	sig, err := jwt.SigningMethodHS384.Sign(signing, []byte(secret))
	if err != nil {
		t.Fatalf("sign hs384: %v", err)
	}
	tok := signing + "." + base64.RawURLEncoding.EncodeToString(sig)
	if _, err := ParseToken(secret, tok); err == nil {
		t.Fatalf("HS384 令牌必须被拒绝（只接受 HS256）")
	}
}

// TestParseTokenAcceptsHS256 反向确认：合法的 HS256 令牌仍可正常解析，避免修复过度。
func TestParseTokenAcceptsHS256(t *testing.T) {
	const secret = "unit-test-secret"
	tok, err := GenerateToken(secret, 7, "alice", "user", 3, "")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	claims, err := ParseToken(secret, tok)
	if err != nil {
		t.Fatalf("合法 HS256 令牌应可解析: %v", err)
	}
	if claims.UserID != 7 || claims.Username != "alice" || claims.TokenVer != 3 {
		t.Fatalf("claims 不符: %+v", claims)
	}
}

// TestParseTokenRejectsExpired 确认过期令牌被拒（回归基本校验未被算法固定破坏）。
func TestParseTokenRejectsExpired(t *testing.T) {
	const secret = "unit-test-secret"
	claims := Claims{
		UserID:   1,
		Username: "admin",
		Role:     "superadmin",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		},
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := ParseToken(secret, tok); err == nil {
		t.Fatalf("过期令牌必须被拒绝")
	}
}

// TestParseTokenRejectsWrongSecret 确认密钥不匹配时拒绝。
func TestParseTokenRejectsWrongSecret(t *testing.T) {
	tok, err := GenerateToken("secret-a", 1, "admin", "superadmin", 0, "")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, err := ParseToken("secret-b", tok); err == nil {
		t.Fatalf("错误密钥签发的令牌必须被拒绝")
	}
}
