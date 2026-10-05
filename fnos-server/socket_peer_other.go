//go:build !linux

package main

import "net"

// unixPeerUID 在非 Linux 平台不支持对端凭据校验，恒返回无法判定（false）。
// 飞牛正式部署为 Linux，此实现仅用于保证本地（如 Windows）构建可编译。
func unixPeerUID(net.Conn) (uint32, bool) { return 0, false }
