// Package web 托管内嵌的 Web 管理后台，并兼容 fnOS 统一网关的应用前缀剥离。
package web

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:dist
var assets embed.FS

// Serve 托管内嵌的 Web 管理后台；/api/ 走后端 fallback，其余回退到 index.html。
// 兼容 fnOS 统一网关（反向代理）：请求可能带 /cryptbox、/apps/cryptbox 等应用前缀，统一剥离。
func Serve(fallback http.Handler) http.Handler {
	dist, err := fs.Sub(assets, "dist")
	if err != nil {
		return fallback
	}
	fileServer := http.FileServer(http.FS(dist))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		// 带前缀的 API 请求（如 /apps/cryptbox/api/status）剥离到 /api/
		if !strings.HasPrefix(p, "/api/") && strings.Contains(p, "/api/") {
			r.URL.Path = p[strings.Index(p, "/api/"):]
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
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
		fileServer.ServeHTTP(w, r)
	})
}
