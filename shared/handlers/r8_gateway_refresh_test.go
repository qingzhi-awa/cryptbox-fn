package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qingzhi-awa/cryptbox/shared/web"
)

// R8-07 网关环境回归：刷新免登录（refresh without re-login）。
//
// 背景：R8-07 之后 Web 后台不再把 JWT 写入 sessionStorage，刷新后 this.token 为空，
// 前端 trySession() 只能“空 token”调 /api/me，靠登录时服务端下发的 HttpOnly Cookie
// 认出身份。飞牛统一网关（Unix Socket 入口）会剥离 Authorization 头，因此这条链路
// 在网关下是**唯一**的续期通道，必须逐条固化，避免以后被改坏。
//
// 本测试模拟网关行为：
//   - 请求带应用前缀 /app/cryptbox（由 shared/web.Serve 剥离并回填 OriginalPath）；
//   - 不发送 Authorization / X-Auth-Token（等价于网关剥离该头）；
//   - 仅凭 Cookie 访问受保护接口。
//
// 覆盖：
//  1) 登录下发会话 Cookie 的属性（Path 限定到应用前缀、HttpOnly、SameSite=Lax）；
//  2) 刷新后 GET /api/me 仅凭 Cookie 即可恢复会话（= 免登录）；
//  3) 刷新后 POST 写接口（网关只转发 GET/POST）仅凭 Cookie 同样可用；
//  4) 负向：无任何凭据必须 401（确认没有放宽鉴权）。
func TestR8GatewayRefreshStaysLoggedIn(t *testing.T) {
	r, _ := newTestServer(t)
	// 用 web.Serve 包一层，等价于飞牛统一网关的反向代理（带应用前缀）。
	h := web.Serve(r)

	const prefix = "/app/cryptbox"

	// —— 建号：走网关前缀的 setup 入口 ——
	if w := gwReq(t, h, http.MethodPost, prefix+"/api/setup", "", `{"username":"admin","password":"AdminPass123"}`); w.Code != http.StatusOK {
		t.Fatalf("setup 失败: %d %s", w.Code, w.Body.String())
	}

	// —— 登录：捕获会话 Cookie ——
	w := gwReq(t, h, http.MethodPost, prefix+"/api/login", "", `{"username":"admin","password":"AdminPass123"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("登录失败: %d %s", w.Code, w.Body.String())
	}
	var cookieVal string
	var sessionCookie *http.Cookie
	for _, ck := range w.Result().Cookies() {
		if ck.Name == authCookieName {
			cookieVal = ck.Value
			sessionCookie = ck
		}
	}
	if cookieVal == "" {
		t.Fatalf("登录未下发 %s 会话 Cookie（Cookie 通道失效 → 网关下刷新将被迫重新登录）", authCookieName)
	}

	// —— 1) Cookie 属性：必须限定到应用前缀、HttpOnly、SameSite=Lax ——
	if sessionCookie.Path != prefix {
		t.Errorf("会话 Cookie Path=%q，期望 %q（否则令牌会外泄给同主机其它服务）", sessionCookie.Path, prefix)
	}
	if !sessionCookie.HttpOnly {
		t.Errorf("会话 Cookie 丢失 HttpOnly（JS 可读 → 削弱 R8-07 的缓解）")
	}
	if sessionCookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("会话 Cookie SameSite=%v，期望 Lax", sessionCookie.SameSite)
	}
	// 网关（Unix Socket）为明文转发，Secure 依赖 c.Request.TLS；此处记录实际取值，
	// 供部署侧核对「网关是否以 HTTPS 面向浏览器」。
	t.Logf("网关环境下会话 Cookie 属性: Path=%q HttpOnly=%v SameSite=%v Secure=%v",
		sessionCookie.Path, sessionCookie.HttpOnly, sessionCookie.SameSite, sessionCookie.Secure)

	cookieHeader := authCookieName + "=" + cookieVal

	// —— 2) 刷新后：仅凭 Cookie 拉 /api/me（= 免登录），不带任何 token 头 ——
	w = gwReq(t, h, http.MethodGet, prefix+"/api/me", cookieHeader, "")
	if w.Code != http.StatusOK {
		t.Fatalf("刷新免登录失败：仅凭 Cookie 访问 /api/me 返回 %d %s", w.Code, w.Body.String())
	}
	var me map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &me)
	if me["username"] != "admin" {
		t.Errorf("Cookie 恢复的会话身份不正确: %v", me["username"])
	}

	// —— 3) 刷新后写操作：网关只转发 GET/POST，POST 等价入口也必须仅凭 Cookie 可用 ——
	w = gwReq(t, h, http.MethodPost, prefix+"/api/me/update", cookieHeader, `{}`)
	if w.Code != http.StatusOK {
		t.Errorf("刷新后 POST 写接口仅凭 Cookie 不可用：%d %s", w.Code, w.Body.String())
	}

	// —— 4) 负向：无凭据必须 401 ——
	if w := gwReq(t, h, http.MethodGet, prefix+"/api/me", "", ""); w.Code != http.StatusUnauthorized {
		t.Errorf("无凭据访问 /api/me 未被拒绝：%d（鉴权被放宽）", w.Code)
	}
}

// TestR8GatewayCookiePathScopedToAppPrefix 验证不同应用前缀下 Cookie 作用域互不干扰：
// 令牌作用域取自 OriginalPath 前缀，第三方应用路径不应拿到同一 Path 的 Cookie。
func TestR8GatewayCookiePathScopedToAppPrefix(t *testing.T) {
	r, _ := newTestServer(t)
	h := web.Serve(r)

	if w := gwReq(t, h, http.MethodPost, "/app/cryptbox/api/setup", "", `{"username":"admin","password":"AdminPass123"}`); w.Code != http.StatusOK {
		t.Fatalf("setup 失败: %d", w.Code)
	}
	// 以另一个应用前缀（/app/other）登录，Cookie Path 应为其自身前缀，而非 /app/cryptbox。
	w := gwReq(t, h, http.MethodPost, "/app/other/api/login", "", `{"username":"admin","password":"AdminPass123"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("登录失败: %d", w.Code)
	}
	for _, ck := range w.Result().Cookies() {
		if ck.Name == authCookieName {
			if ck.Path != "/app/other" {
				t.Errorf("非本应用前缀下 Cookie Path=%q，期望 /app/other", ck.Path)
			}
			return
		}
	}
	t.Fatalf("未下发会话 Cookie")
}

// gwReq 以网关视角发起请求：path 含应用前缀；不发送 Authorization/X-Auth-Token
// （等价于飞牛网关剥离该头），仅在 cookie 非空时附带 Cookie 头。
func gwReq(t *testing.T, h http.Handler, method, path, cookie, body string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *strings.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	} else {
		rdr = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Content-Type", "application/json")
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}
