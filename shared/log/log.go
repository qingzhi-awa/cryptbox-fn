// Package log 提供操作日志记录与保留策略裁剪。
package log

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
)

// 日志保留策略：最多保留条数与天数，达到任意一个限制即淘汰最旧日志。
const (
	MaxEntries = 999
	MaxAgeDays = 365
)

// Info 输出运行时信息到标准日志（fpk 部署下会写入数据目录 info.log）。
// 用于 API 访问记录等排查信息。
func Info(format string, args ...interface{}) {
	log.Printf("[INFO] "+format, args...)
}

// LogAction 记录一条操作日志（尽力而为，不阻塞主流程），
// 写入后按策略裁剪：超过 MaxEntries 条或超过 MaxAgeDays 天的旧日志逐条删除。
func LogAction(db *sql.DB, userID int64, username, action, detail, ip string) {
	if db == nil {
		return
	}
	_, _ = db.Exec(`INSERT INTO logs (user_id, username, action, detail, ip) VALUES (?, ?, ?, ?, ?)`,
		userID, username, action, detail, ip)
	// 条数超限：仅保留最新 MaxEntries 条（新日志进一条，最旧的一条被替换掉）
	_, _ = db.Exec(`DELETE FROM logs WHERE id <= (SELECT id FROM logs ORDER BY id DESC LIMIT 1 OFFSET ?)`, MaxEntries-1)
	// 天数超限：删除超过保留天数的旧日志
	_, _ = db.Exec(`DELETE FROM logs WHERE created_at < datetime('now', ?)`, fmt.Sprintf("-%d days", MaxAgeDays))
}

// TrustProxyHeaders 决定 ClientIP 是否采信 X-Forwarded-For / X-Real-IP。
// 默认 false：直接使用 TCP 连接的远端地址，防止客户端伪造来源 IP 污染审计日志。
// 仅当服务确实部署在受信反向代理之后时，入口才应将其置为 true（对应 TRUST_PROXY=true）。
var TrustProxyHeaders = false

// xffTrustKey 是请求上下文中「本请求是否采信代理头」的覆盖标记。
// 飞牛端有两个入口：统一网关 Unix Socket（网关注入的 XFF 可信）与直连 TCP
// 端口（XFF 可能是攻击者伪造）。进程级开关无法区分两者，入口必须按监听器
// 用 WithXFFTrust 显式标注，防止直连请求伪造 XFF 绕过全部 IP 限流。
type xffTrustKeyType struct{}

var xffTrustKey xffTrustKeyType

// WithXFFTrust 返回一个带 XFF 信任决策的请求副本：trust=true 时无条件采信
// X-Forwarded-For / X-Real-IP，false 时无条件不采信；两者都覆盖进程级开关。
func WithXFFTrust(r *http.Request, trust bool) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), xffTrustKey, trust))
}

// XFFTrustMiddleware 返回为每个请求标注 XFF 信任决策的 handler 包装，
// 供服务入口按监听器区分：网关 Unix Socket 传 true（网关注入的 XFF 可信），
// 直连 TCP 端口传 false（XFF 可能被客户端伪造），均覆盖进程级开关。
func XFFTrustMiddleware(h http.Handler, trust bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, WithXFFTrust(r, trust))
	})
}

// ProxyTrusted 返回「本请求是否采信 X-Forwarded-* 代理头」的决策，口径与 ClientIP 完全一致：
// 入口按监听器写入的上下文标记优先，未标注时回退到进程级开关 TrustProxyHeaders。
// 除来源 IP 外，Cookie 的 Secure 判定（X-Forwarded-Proto）也必须复用同一决策，
// 否则直连请求可伪造转发头骗出 Secure 属性或污染来源 IP。
func ProxyTrusted(r *http.Request) bool {
	if v, ok := r.Context().Value(xffTrustKey).(bool); ok {
		return v
	}
	return TrustProxyHeaders
}

// ClientIP 从请求中提取客户端 IP。
func ClientIP(r *http.Request) string {
	trustProxy := ProxyTrusted(r)
	if trustProxy {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			if first := strings.TrimSpace(strings.Split(fwd, ",")[0]); first != "" {
				return first
			}
		}
		if real := strings.TrimSpace(r.Header.Get("X-Real-IP")); real != "" {
			return real
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return strings.TrimSpace(host)
	}
	return strings.TrimSpace(r.RemoteAddr)
}
