// Package auth 提供密码哈希（bcrypt）、JWT 签发/校验与角色权限判定。
package auth

import (
	"errors"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// HashPassword 使用 bcrypt 哈希密码。
// bcryptCost 口令哈希成本：12（约 4 倍于默认 10 的暴力破解代价）。
// 存量用户口令不受影响，仅在下次设置/修改口令时按新成本计算。
const bcryptCost = 12

func HashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// CheckPassword 校验密码与哈希是否匹配。
func CheckPassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

// Claims JWT 载荷。
//
// TokenVer 为「令牌版本」（PT-06）：与 users.token_version 比对，不一致即视为失效。
// JWT 本身无法吊销，该字段补上了「改密码后旧令牌立即作废」的能力。
type Claims struct {
	UserID   int64  `json:"uid"`
	Username string `json:"username"`
	Role     string `json:"role"`
	TokenVer int64  `json:"ver"`
	// FnUID 是签发该令牌时飞牛统一网关标识的访问者身份（X-Trim-Userid，缺失时回退用户名）。
	// 为空表示非网关场景（如直连端口），此时不参与校验。会话据此与飞牛账号绑定：
	// 切换飞牛账号后，旧令牌携带的 FnUID 与新账号不一致，服务端立即拒绝并要求重新登录。
	FnUID string `json:"fnu,omitempty"`
	jwt.RegisteredClaims
}

// TokenTTL 是签发的 JWT 有效期，默认 24 小时。
//
// 服务端每次请求都回查 users.status / token_version，可即时吊销；缩短有效期可
// 进一步缩小 token 泄露后的可用窗口。可用环境变量 TOKEN_TTL_HOURS 覆盖（1..168）。
var TokenTTL = func() time.Duration {
	const def = 24 * time.Hour
	v := os.Getenv("TOKEN_TTL_HOURS")
	if v == "" {
		return def
	}
	h, err := strconv.Atoi(v)
	if err != nil || h < 1 || h > 168 {
		return def
	}
	return time.Duration(h) * time.Hour
}()

// GenerateToken 签发有效期为 TokenTTL 的 JWT。tokenVer 与用户当前的令牌版本一致。
// fnUID 标识签发时的飞牛网关用户身份（非网关场景传空串），用于会话与飞牛账号绑定。
func GenerateToken(secret string, userID int64, username, role string, tokenVer int64, fnUID string) (string, error) {
	claims := Claims{
		UserID:   userID,
		Username: username,
		Role:     role,
		TokenVer: tokenVer,
		FnUID:    fnUID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(TokenTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
}

// ParseToken 解析并校验 JWT。
func ParseToken(secret, tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}

// CanManageUser 判断 operatorRole 是否有权管理 targetRole。
func CanManageUser(operatorRole, targetRole string) bool {
	if operatorRole == "superadmin" {
		return true
	}
	if operatorRole == "admin" {
		return targetRole == "user" || targetRole == "admin"
	}
	return false
}
