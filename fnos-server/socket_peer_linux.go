//go:build linux

package main

import (
	"net"

	"golang.org/x/sys/unix"
)

// unixPeerUID 返回 unix 域套接字连接对端的 UID（Linux SO_PEERCRED）。
// 第二个返回值为 false 表示无法判定对端凭据（非 unix 连接或系统调用失败）。
func unixPeerUID(c net.Conn) (uint32, bool) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, false
	}
	var (
		cred *unix.Ucred
		serr error
	)
	if cerr := raw.Control(func(fd uintptr) {
		cred, serr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); cerr != nil || serr != nil || cred == nil {
		return 0, false
	}
	return cred.Uid, true
}
