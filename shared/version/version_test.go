package version

import "testing"

// TestBuildTagOf 锁定摘要算法：前端 web/src/main.js 的 buildTagOf 必须产出相同结果，
// 否则「页面版本是否与服务端一致」的自检会误判，导致反复自动刷新。
func TestBuildTagOf(t *testing.T) {
	cases := map[string]string{
		"0.2.29": "92f2cdc2", // 由 JS 实现计算得出（见 main.js buildTagOf）
		"dev":    "d55997bc", // 与本地未注入版本号时的 /api/status 一致
	}
	for v, want := range cases {
		if got := BuildTagOf(v); got != want {
			t.Fatalf("BuildTagOf(%q) = %q，期望 %q（需与前端实现保持一致）", v, got, want)
		}
	}
}
