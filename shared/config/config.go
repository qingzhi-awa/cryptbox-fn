// Package config 加载服务端配置（通过环境变量注入）。
package config

import (
	"os"
	"path/filepath"
	"strings"
)

// Config 服务端配置，通过环境变量注入。
type Config struct {
	Port      string // TCP 监听端口（客户端局域网同步用）
	SockPath  string // 统一网关 Unix Socket 路径（飞牛 fpk 运行时注入，空表示不监听）
	DBDSN     string // SQLite 数据库文件路径
	JWTSecret string // JWT 签名密钥。无内置默认值，必须由入口在启动时从数据库读取或随机生成后覆盖。

	// TLSCert / TLSKey 同时提供时启用 HTTPS；否则以明文 HTTP 提供服务（应配合反向代理使用）。
	TLSCert string
	TLSKey  string

	// CORSOrigins 允许的跨域来源白名单（精确匹配，如 https://a.example）。
	// 留空表示不下发任何跨域响应头，浏览器仅允许同源访问——这是推荐默认值。
	CORSOrigins []string

	// TrustProxy 为 true 时才信任 X-Forwarded-For 等代理头。
	// 仅在服务确实部署于受信反向代理之后时开启，否则客户端可伪造来源 IP。
	TrustProxy bool

	// ForceHTTPS 为 true 时强制安全传输：
	//   - 自带 TLS 的服务端（server / fnos-server）：未配置 TLS_CERT/TLS_KEY 将拒绝启动；
	//   - 反代部署的 website：非 HTTPS 请求（按 X-Forwarded-Proto 判定）301 重定向到 HTTPS。
	// localhost / 127.0.0.1 访问始终豁免，便于本机管理。
	ForceHTTPS bool

	// HTTPRedirectPort 可选：TLS 模式下额外监听一个明文端口，把 HTTP 请求 301
	// 重定向到 HTTPS（如 HTTP_REDIRECT_PORT=80）。未设置则不监听明文端口。
	HTTPRedirectPort string

	// DisableTLS 为 true 时跳过 HTTPS（不使用环境变量证书、不自动发现、
	// 不自动生成），以明文 HTTP 运行——仅供完全本机使用的特殊场景，
	// 与 FORCE_HTTPS 互斥。
	DisableTLS bool
}

// DataDir 返回数据目录：飞牛 FPK 运行时优先使用 TRIM_PKGVAR，否则当前目录。
func DataDir() string {
	if d := os.Getenv("TRIM_PKGVAR"); d != "" {
		return d
	}
	return "."
}

// Load 从环境变量加载配置，端口默认 5201（fnos-server）。
// 通用服务器（server/）可调用后覆盖 Port 为 5018。
func Load() Config {
	return Config{
		Port:      GetEnv("PORT", "5201"),
		SockPath:  os.Getenv("GATEWAY_SOCK"),
		DBDSN:     GetEnv("DB_DSN", filepath.Join(DataDir(), "app.db")),
		JWTSecret: os.Getenv("JWT_SECRET"), // 故意不设默认值，避免可预测密钥
		TLSCert:   os.Getenv("TLS_CERT"),
		TLSKey:    os.Getenv("TLS_KEY"),
		CORSOrigins: splitList(os.Getenv("CORS_ORIGINS")),
		TrustProxy:  GetEnv("TRUST_PROXY", "") == "true",
		ForceHTTPS:  GetEnv("FORCE_HTTPS", "") == "true",
		HTTPRedirectPort: os.Getenv("HTTP_REDIRECT_PORT"),
		DisableTLS:  GetEnv("DISABLE_TLS", "") == "true",
	}
}

// TLSEnabled 返回是否配置了完整的 TLS 证书对。
func (c Config) TLSEnabled() bool {
	return c.TLSCert != "" && c.TLSKey != ""
}

// AutoDetectTLS 在未显式配置证书时，探测数据目录下的证书文件并自动启用 HTTPS。
// 依次查找 tls.crt + tls.key、cert.pem + key.pem。
// 为 fpk / NAS 场景设计：把证书文件放进应用数据目录（TRIM_PKGVAR）即可，
// 无需修改启动参数。返回是否发现了证书。
func (c *Config) AutoDetectTLS() bool {
	if c.TLSEnabled() {
		return false
	}
	for _, pair := range [][2]string{{"tls.crt", "tls.key"}, {"cert.pem", "key.pem"}} {
		crt := filepath.Join(DataDir(), pair[0])
		key := filepath.Join(DataDir(), pair[1])
		if _, err := os.Stat(crt); err != nil {
			continue
		}
		if _, err := os.Stat(key); err != nil {
			continue
		}
		c.TLSCert = crt
		c.TLSKey = key
		return true
	}
	return false
}

// GetEnv 读取环境变量，空值返回默认值。
func GetEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// splitList 将逗号分隔的字符串切分为去除空白的列表。
func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}
