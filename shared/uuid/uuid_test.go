package uuid

import (
	"strings"
	"testing"
)

// TestNewV4FormatAndUniqueness 校验收随机 UUID 的格式与唯一性。
func TestNewV4FormatAndUniqueness(t *testing.T) {
	seen := make(map[string]bool, 1000)
	for i := 0; i < 1000; i++ {
		u := NewV4()
		if !IsValid(u) {
			t.Fatalf("格式非法: %q", u)
		}
		if u[14] != '4' {
			t.Fatalf("version 位应为 4: %q", u)
		}
		if !strings.ContainsRune("89ab", rune(u[19])) {
			t.Fatalf("variant 位非法: %q", u)
		}
		if seen[u] {
			t.Fatalf("出现重复 UUID: %q", u)
		}
		seen[u] = true
	}
}

// TestNewV5Deterministic 校验确定性 UUID：同输入恒等，异输入不同。
func TestNewV5Deterministic(t *testing.T) {
	a1 := NewV5(Namespace, "100:1")
	a2 := NewV5(Namespace, "100:1")
	if a1 != a2 {
		t.Fatalf("同输入应得到相同 uuid: %q vs %q", a1, a2)
	}
	if a1 == NewV5(Namespace, "100:2") {
		t.Fatal("不同 id 不应得到相同 uuid")
	}
	if a1[14] != '5' {
		t.Fatalf("version 位应为 5: %q", a1)
	}
	if !IsValid(a1) {
		t.Fatalf("格式非法: %q", a1)
	}
}

// TestDeterministicScoping 校验确定性标识按用户隔离：
// 不同用户使用相同本地 id 时必须得到不同 uuid（否则跨用户身份会串）。
func TestDeterministicScoping(t *testing.T) {
	a := Deterministic(100, 1)
	b := Deterministic(200, 1)
	if a == b {
		t.Fatalf("不同用户同 id 不应得到相同 uuid: %q", a)
	}
	if !IsValid(a) {
		t.Fatalf("格式非法: %q", a)
	}
}

// TestDeterministicFrozenVectors 固化确定性向量。
//
// 这些值由命名空间 + 算法共同决定，一旦变化说明**已发布条目的同步标识会整体漂移**
// （客户端会认为是全新条目）。因此把它们锁定为回归断言，防止无意修改。
func TestDeterministicFrozenVectors(t *testing.T) {
	cases := []struct {
		userID, legacyID int64
		want             string
	}{
		{1, 1, "e00c53a1-026e-5018-9e6d-5b8b72dfb021"},
		{100, 1, "effa57e6-6424-5215-8e9b-6079b24dfabf"},
		{200, 1, "18266506-29d7-584a-86b2-4d80e44e8a40"},
	}
	for _, c := range cases {
		if got := Deterministic(c.userID, c.legacyID); got != c.want {
			t.Fatalf("确定性向量已变化（会导致存量条目身份漂移）：Deterministic(%d,%d)=%q 期望 %q",
				c.userID, c.legacyID, got, c.want)
		}
	}
}

// TestIsValid 校验格式判定。
func TestIsValid(t *testing.T) {
	if !IsValid("aaaaaaaa-0000-4000-8000-000000000001") {
		t.Fatal("合法 UUID 被拒")
	}
	if !IsValid("AAAAAAAA-0000-4000-8000-000000000001") {
		t.Fatal("大写 UUID 应被接受")
	}
	for _, bad := range []string{"", "abc", "aaaaaaaa-0000-4000-8000-00000000000", "aaaaaaaa000040008000000000000001",
		"zzzzzzzz-0000-4000-8000-000000000001", "aaaaaaaa-0000-4000-8000-000000000001-"} {
		if IsValid(bad) {
			t.Fatalf("非法值被接受: %q", bad)
		}
	}
}
