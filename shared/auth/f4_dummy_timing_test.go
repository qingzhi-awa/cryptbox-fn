package auth

import (
	"sort"
	"testing"
	"time"
)

// F4 回归测试：登录失败路径的恒定耗时比对。
//
// 背景：handleLogin 原先用 `err == sql.ErrNoRows || (err == nil && !CheckPassword(...))`
// 短路——用户不存在时完全跳过 bcrypt 比对，使「存在 + 错口令」与「不存在」的响应时间
// 相差数倍，攻击者仅凭计时即可枚举账号。修复：不存在时也对固定 dummy 哈希做一次比对。
//
// 本测试直接验证 DummyPasswordCheck 的耗时与真实 bcrypt 校验同量级。
func TestF4DummyPasswordCheckCostsComparableToReal(t *testing.T) {
	hash, err := HashPassword("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	real := measure(3, func() { CheckPassword(hash, "wrong-password") })
	dummy := measure(3, func() { DummyPasswordCheck("wrong-password") })
	realMed, dummyMed := median(real), median(dummy)
	if dummyMed < realMed/2 {
		t.Fatalf("dummy 比对中位耗时 %v 明显低于真实比对 %v，仍可据计时枚举账号", dummyMed, realMed)
	}
}

func measure(n int, fn func()) []time.Duration {
	out := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		start := time.Now()
		fn()
		out = append(out, time.Since(start))
	}
	return out
}

func median(d []time.Duration) time.Duration {
	if len(d) == 0 {
		return 0
	}
	cp := append([]time.Duration(nil), d...)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	return cp[len(cp)/2]
}
