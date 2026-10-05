package handlers

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/qingzhi-awa/cryptbox/shared/log"
)

// R9-02 回归测试：会话 Cookie 的 Secure 判定。
//
// 背景：网关经 Unix Socket 明文转发，`c.Request.TLS` 恒为 nil，原先 `Secure:
// c.Request.TLS != nil` 使 Cookie 永远不带 Secure（低危）。修复后改为：直连 TLS 为真；
// 经反向代理/网关时，仅在【采信代理头】且 X-Forwarded-Proto 首个值为 "https" 时为真。
//
// 安全约束：转发头必须受信任判定约束（log.ProxyTrusted，与 clientIP 同一口径），
// 否则直连客户端可伪造 `X-Forwarded-Proto: https` 骗服务端下发 Secure Cookie。
func TestR9CookieSecureFollowsTrustedProto(t *testing.T) {
	cases := []struct {
		name       string
		tls        bool
		trustProxy bool
		proto      string
		want       bool
	}{
		{"直连真 TLS", true, false, "", true},
		{"网关(信任代理)+XFP=https", false, true, "https", true},
		{"网关(信任代理)+XFP=http", false, true, "http", false},
		{"网关(信任代理)+无 XFP", false, true, "", false},
		{"直连伪造 XFP=https（不信任代理）", false, false, "https", false},
		{"XFP 多值取首个 https", false, true, "https, http", true},
		{"XFP 多值取首个 http", false, true, "http, https", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			req := httptest.NewRequest(http.MethodPost, "/api/login", nil)
			if tc.proto != "" {
				req.Header.Set("X-Forwarded-Proto", tc.proto)
			}
			if tc.tls {
				req.TLS = &tls.ConnectionState{}
			}
			// 入口按监听器标注的代理信任决策（网关 Unix Socket=true，直连=false）。
			req = log.WithXFFTrust(req, tc.trustProxy)
			c.Request = req
			if got := secureRequest(c); got != tc.want {
				t.Errorf("secureRequest=%v，期望 %v", got, tc.want)
			}
		})
	}
}
