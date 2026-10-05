// Package web 托管内嵌的 Web 管理后台，并兼容 fnOS 统一网关的应用前缀剥离。
package web

import (
	"context"
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:dist
var assets embed.FS

// ContentSecurityPolicy 是 Web 管理后台下发的 CSP。
//
// 设计依据（逐指令）：
//   - default-src 'self'      ：默认全部同源，杜绝外部资源注入；
//   - script-src 'self'       ：仅同源脚本，**既不放行 'unsafe-eval' 也不放行 'unsafe-inline'**。
//     构建期已把 vue-i18n 切到 AST 解释器（vite.config.js 中 `__INTLIFY_JIT_COMPILATION__=true`），
//     产物不再包含 `new Function`，因此无需 eval；内联 <script> 与事件属性同样被阻断
//     （这是 XSS 的主要面）。
//   - style-src 'self' 'unsafe-inline'：Vue 运行时会注入内联 <style>，必须放行；
//   - img-src 'self' data: blob:：头像/图标为同源，data:/blob: 供本地上传预览；
//   - font-src 'self' data:   ：字体同源或内联；
//   - connect-src 'self'      ：API 全部为同源相对路径（fetch('api/...')）；
//   - object-src 'none'       ：禁用 <object>/<embed>/<applet>；
//   - base-uri 'self'         ：阻止通过 <base> 劫持相对链接；
//   - form-action 'self'      ：表单只能提交到同源。
//
// 重要：**故意不下发 frame-ancestors**。本应用需要被 fnOS 桌面以 iframe 形式
// 内嵌（与 fnOS 桌面不同源），'none'/'self' 都会阻止该集成——与同处不下发
// X-Frame-Options 的既有决策保持一致。
const ContentSecurityPolicy = "default-src 'self'; " +
	"script-src 'self'; " +
	"style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data: blob:; " +
	"font-src 'self' data:; " +
	"connect-src 'self'; " +
	"object-src 'none'; " +
	"base-uri 'self'; " +
	"form-action 'self'"

type ctxKey struct{ name string }

var originalPathKey = ctxKey{"cryptbox-original-path"}

// OriginalPath 返回网关前缀被剥离之前的原始请求路径（例如 /app/cryptbox/api/login）。
// 用途：会话 Cookie 需要按应用前缀限定作用域，避免令牌被送往同一主机上的其他服务。
func OriginalPath(r *http.Request) string {
	if v, ok := r.Context().Value(originalPathKey).(string); ok {
		return v
	}
	return ""
}

// Serve 托管内嵌的 Web 管理后台；/api/ 走后端 fallback，其余回退到 index.html。
// 兼容 fnOS 统一网关（反向代理）：请求可能带 /cryptbox、/apps/cryptbox 等应用前缀，统一剥离。
func Serve(fallback http.Handler) http.Handler {
	dist, err := fs.Sub(assets, "dist")
	if err != nil {
		return fallback
	}
	fileServer := http.FileServer(http.FS(dist))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 文档与静态资源由本函数直接返回，不经过 gin 中间件，因此安全响应头需在此下发。
		// 注意：不下发 X-Frame-Options——本应用需要被 fnOS 桌面以 iframe 形式内嵌。
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		// CSP 作为第二道防线（见 ContentSecurityPolicy 说明；故意不含 frame-ancestors）。
		w.Header().Set("Content-Security-Policy", ContentSecurityPolicy)
		if r.TLS != nil {
			// 仅在真实 TLS 连接上下发 HSTS：飞牛统一网关经明文 socket 转发应用响应，
			// 若在此透传 HSTS，会以 NAS 主机名记录长达一年的强制 HTTPS。
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		p := r.URL.Path
		// 带前缀的 API 请求（如 /apps/cryptbox/api/status）剥离到 /api/
		if !strings.HasPrefix(p, "/api/") && strings.Contains(p, "/api/") {
			r.URL.Path = p[strings.Index(p, "/api/"):]
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			// 把剥离前的原始路径带给下游（用于按应用前缀限定会话 Cookie 作用域）。
			r = r.WithContext(context.WithValue(r.Context(), originalPathKey, p))
			fallback.ServeHTTP(w, r)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path != "" {
			if _, err := fs.Stat(dist, path); err != nil {
				// 尝试逐段剥离网关前缀后匹配静态文件（如 /apps/cryptbox/assets/x.js）
				p2 := path
				for {
					i := strings.Index(p2, "/")
					if i < 0 {
						break
					}
					p2 = p2[i+1:]
					if _, err2 := fs.Stat(dist, p2); err2 == nil {
						path = p2
						break
					}
				}
				if _, err2 := fs.Stat(dist, path); err2 != nil {
					r.URL.Path = "/" // SPA 回退
				} else {
					r.URL.Path = "/" + path
				}
			}
		}
		// 缓存策略：升级后必须立刻生效，否则浏览器会继续使用旧前端（曾导致「装了新版却仍是旧行为」）。
		//   · 带内容哈希的构建产物（/assets/...）→ 长期强缓存；
		//   · 其余（index.html、SPA 回退、favicon 等）→ 禁止缓存，每次向服务端确认。
		if strings.HasPrefix(r.URL.Path, "/assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
		}
		fileServer.ServeHTTP(w, r)
	})
}
