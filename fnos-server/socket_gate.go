package main

import (
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

// gatewayUID 解析 GATEWAY_UID 环境变量（十进制 UID）。未设置或非法时返回 (0,false)。
//
// 用途（F6）：统一网关 Unix Socket 是以 0660 暴露的，且 socket 入口信任
// X-Forwarded-For。属组内的任意进程都能连接并伪造来源 IP，从而绕过 IP 维度限流/锁定、
// 污染审计来源。配置 GATEWAY_UID 后，仅接受该 UID 的连接，把信任边界从「整个属组」
// 收紧到「网关进程本身」。未配置时保持既有行为（仅打印残余风险提示）。
func gatewayUID() (uint32, bool) {
	v := strings.TrimSpace(os.Getenv("GATEWAY_UID"))
	if v == "" {
		return 0, false
	}
	n, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		log.Printf("警告：GATEWAY_UID=%q 不是合法 UID，已忽略对端凭据校验", v)
		return 0, false
	}
	return uint32(n), true
}

// uidGateListener 只接受来自指定 UID 的连接。对端凭据无法判定或 UID 不匹配时直接
// 断开，不进入 HTTP 处理（阻止属组内其他进程借 socket 伪造代理头）。
type uidGateListener struct {
	net.Listener
	allowUID uint32
}

func (l uidGateListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if uid, ok := unixPeerUID(c); ok && uid == l.allowUID {
			return c, nil
		}
		_ = c.Close()
	}
}
