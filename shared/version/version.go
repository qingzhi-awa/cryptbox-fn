// Package version 暴露构建版本号，便于在界面上确认当前运行的前端/服务端版本。
//
// 默认值 "dev"；打包时由 fnos-server/build.ps1 通过
//   -ldflags "-X github.com/qingzhi-awa/cryptbox/shared/version.Version=<manifest version>"
// 注入，保证与 manifest / 安装包版本一致。
package version

import "fmt"

// Version 形如 "0.2.13"；未注入时为 "dev"。
var Version = "dev"

// BuildTag 返回版本号的短摘要（FNV-1a 32 位，8 位十六进制）。
//
// 用途：前端用它做「页面版本是否与服务端一致」的自检——只需比较"是否变化"，
// 无需把精确版本号暴露给未认证请求。算法在前后端各实现一份（见 web/src/main.js），
// 必须保持一致（非加密用途，仅需确定性）。
func BuildTag() string {
	return BuildTagOf(Version)
}

// BuildTagOf 计算任意版本字符串的短摘要。
func BuildTagOf(v string) string {
	var h uint32 = 2166136261
	for i := 0; i < len(v); i++ {
		h ^= uint32(v[i])
		h *= 16777619
	}
	return fmt.Sprintf("%08x", h)
}
