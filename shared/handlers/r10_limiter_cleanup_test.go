package handlers

import (
	"reflect"
	"testing"

	"github.com/qingzhi-awa/cryptbox/shared/config"
)

// cleaner 是所有限流器（*ratelimit.Limiter / *ratelimit.FailLocker）都实现的接口。
type cleaner interface{ Cleanup() }

// R10-01 回归：Server 上**每一个**限流器都必须被登记进周期性清理列表。
//
// 背景：限流器的键来自攻击者可控的输入（来源 IP、邮箱、账号名），若不周期性
// Cleanup，进程内 map 会无限增长。原实现逐条硬编码调用，`setupIP` 曾被遗漏
// ——单看代码很难发现，因此这里用反射把"新增限流字段必须同步登记"变成硬约束。
func TestAllLimitersAreCleaned(t *testing.T) {
	s := NewServer(config.Config{}, nil, nil)

	cleanerType := reflect.TypeOf((*cleaner)(nil)).Elem()
	sv := reflect.ValueOf(s).Elem()
	st := sv.Type()

	// 收集 Server 上所有实现了 Cleanup() 的（非 nil）指针字段：字段名 → 指针地址。
	fields := map[string]uintptr{}
	for i := 0; i < st.NumField(); i++ {
		f := st.Field(i)
		if !f.Type.Implements(cleanerType) {
			continue
		}
		fv := sv.Field(i)
		if fv.IsNil() {
			continue
		}
		fields[f.Name] = fv.Pointer()
	}
	if len(fields) == 0 {
		t.Fatal("未在 Server 上找到任何限流器字段，测试本身已失效")
	}

	// 清理列表里的每个对象都必须对应一个字段，且不重复。
	seen := map[string]bool{}
	for _, l := range s.limiters() {
		if l == nil {
			t.Fatal("清理列表中存在 nil 限流器")
		}
		p := reflect.ValueOf(l).Pointer()
		name := ""
		for n, fp := range fields {
			if fp == p {
				name = n
				break
			}
		}
		if name == "" {
			t.Fatalf("清理列表中的 %T(%p) 不对应 Server 的任何限流字段", l, l)
		}
		if seen[name] {
			t.Fatalf("限流字段 %s 在清理列表里重复登记", name)
		}
		seen[name] = true
	}

	// 反向断言：任何限流字段都不能漏登记。
	for n := range fields {
		if !seen[n] {
			t.Fatalf("限流字段 %s 未加入周期性清理，其键表会无限增长（R10-01 同类缺陷）", n)
		}
	}
}
