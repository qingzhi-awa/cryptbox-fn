// Package config 加载服务端配置（通过环境变量注入）。
package config

import (
	"os"
	"path/filepath"
)

// Config 服务端配置，通过环境变量注入。
type Config struct {
	Port      string // TCP 监听端口（客户端局域网同步用）
	SockPath  string // 统一网关 Unix Socket 路径（飞牛 fpk 运行时注入，空表示不监听）
	DBDSN     string // SQLite 数据库文件路径
	JWTSecret string // JWT 签名密钥
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
		JWTSecret: GetEnv("JWT_SECRET", "change-this-secret"),
	}
}

// GetEnv 读取环境变量，空值返回默认值。
func GetEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
