package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qingzhi-awa/cryptbox/shared/web"
)

// R6-03：Web 管理后台无 CSP（桌面端有、Web 端无），作为第二道防线补齐。
//
// 期望：
//  1. API 路径（gin 中间件链）的响应携带 Content-Security-Policy；
//  2. 静态/文档路径（web.Serve 直接返回，不经过 gin）的响应同样携带；
//  3. CSP 不得包含 frame-ancestors 'none'/'self'（会阻断 fnOS 桌面 iframe 内嵌）；
//  4. CSP 不得放行 script-src 'unsafe-inline'（内联脚本是 XSS 主要注入面）。
func TestCSPHeaderPresentAndCorrect(t *testing.T) {
	r, _ := newTestServer(t)

	// 1) API 路径。
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	csp := w.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("API 响应缺少 Content-Security-Policy 头")
	}
	assertCSPShape(t, csp)

	// 2) 静态路径（经 web.Serve 托管的内嵌后台，不经过 gin 中间件链）。
	handler := web.Serve(r)
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("首页应返回 200，实际 %d", w2.Code)
	}
	csp2 := w2.Header().Get("Content-Security-Policy")
	if csp2 == "" {
		t.Fatal("静态页面响应缺少 Content-Security-Policy 头")
	}
	assertCSPShape(t, csp2)
}

// assertCSPShape 校验 CSP 的关键形态约束。
func assertCSPShape(t *testing.T, csp string) {
	t.Helper()
	// 不得阻断 fnOS 桌面 iframe 内嵌（与"不下发 X-Frame-Options"的既有决策一致）。
	for _, banned := range []string{"frame-ancestors 'none'", "frame-ancestors 'self'"} {
		if strings.Contains(csp, banned) {
			t.Fatalf("CSP 包含 %q，会阻断 fnOS 桌面 iframe 内嵌集成", banned)
		}
	}
	// 不得放行内联脚本（XSS 主要注入面）。
	if strings.Contains(csp, "script-src") && strings.Contains(csp, "'unsafe-inline'") &&
		scriptSrcAllowsUnsafeInline(csp) {
		t.Fatal("CSP 的 script-src 放行了 'unsafe-inline'，内联脚本注入面未被阻断")
	}
	// 核心指令必须在。
	for _, must := range []string{
		"default-src 'self'", "script-src", "style-src",
		"connect-src 'self'", "object-src 'none'", "base-uri",
	} {
		if !strings.Contains(csp, must) {
			t.Fatalf("CSP 缺少关键指令 %q（实际：%s）", must, csp)
		}
	}
}

// scriptSrcAllowsUnsafeInline 解析 CSP 中 script-src 指令的取值，
// 判断其是否含 'unsafe-inline'（style-src 允许 inline 不算）。
func scriptSrcAllowsUnsafeInline(csp string) bool {
	for _, directive := range strings.Split(csp, ";") {
		d := strings.TrimSpace(directive)
		if strings.HasPrefix(d, "script-src") {
			return strings.Contains(d, "'unsafe-inline'")
		}
	}
	return false
}
