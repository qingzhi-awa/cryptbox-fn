package handlers

import (
	"fmt"
	"sync"
	"testing"

	"github.com/qingzhi-awa/cryptbox/shared/db"
)

// TestConcurrentUserCreationStress 是 VULN D 修复的高强度压测：
// 在比 TestConcurrentUserCreationNoIDCollision 更极端的竞争下验证「随机退避重试」仍能收敛。
//
// 目的：随机退避是概率性收敛的，必须证明在更高并发 + 更严苛调度下不出现
// 「重试次数用尽」或主键冲突，否则修复只是把失败概率降低而非消除。
// 用 -race 运行时同时保证无数据竞争。
func TestConcurrentUserCreationStress(t *testing.T) {
	if testing.Short() {
		t.Skip("压测用例，-short 下跳过")
	}
	_, database := newTestServer(t)

	// 给足重试预算：这里要验证的是"能否收敛"，不是"快速失败"。
	db.SetUserIDRetryBaseForTest(0) // 0 = 使用生产默认（64 次）
	t.Cleanup(func() { db.SetUserIDRetryBaseForTest(0) })

	const batches = 4
	const perBatch = 32
	const total = batches * perBatch

	var wg sync.WaitGroup
	results := make([]error, total)
	ids := make([]int64, total)

	// 多批次错峰起跑，制造"持续竞争"而非一次性脉冲。
	for b := 0; b < batches; b++ {
		wg.Add(perBatch)
		for i := 0; i < perBatch; i++ {
			idx := b*perBatch + i
			go func(idx int) {
				defer wg.Done()
				name := fmt.Sprintf("stress_%04d", idx)
				id, err := db.CreateUserWithNextID(database, name, "$2a$12$abcdefghijklmnopqrstuv", "user", name+"@example.com", "", "")
				results[idx] = err
				ids[idx] = id
			}(idx)
		}
	}
	wg.Wait()

	failed := 0
	for i, err := range results {
		if err != nil {
			failed++
			if failed <= 5 {
				t.Errorf("压测第 %d 个失败: %v", i, err)
			}
		}
	}
	if failed > 0 {
		t.Fatalf("压测共 %d/%d 个失败（随机退避未收敛）", failed, total)
	}

	// 全部落库且 id 唯一（无重复、无空洞外的错位）。
	var count int
	if err := database.QueryRow(`SELECT COUNT(1) FROM users WHERE username LIKE 'stress_%'`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != total {
		t.Fatalf("期望 %d 个用户，实际 %d", total, count)
	}

	seen := map[int64]bool{}
	for _, id := range ids {
		if id <= 0 {
			t.Fatalf("出现非正 id：%d", id)
		}
		if seen[id] {
			t.Fatalf("出现重复 id：%d", id)
		}
		seen[id] = true
	}
}
