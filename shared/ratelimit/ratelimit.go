// Package ratelimit 提供进程内的固定窗口限流与失败锁定控制。
//
// 定位：面向单实例部署的轻量防护（本项目默认部署形态）。
// 若未来改为多实例集群，应将这些状态迁移到共享存储（如 Redis）后再启用。
package ratelimit

import (
	"sync"
	"time"
)

// window 是某个键在当前固定窗口内的计数。
type window struct {
	count int
	reset time.Time
}

// Limiter 对任意字符串键做固定窗口限流。
type Limiter struct {
	mu     sync.Mutex
	m      map[string]*window
	limit  int
	period time.Duration
}

// New 创建一个限流器：在 period 时间内最多允许 limit 次。
// limit <= 0 表示不限制（返回的 Allow 恒为 true）。
func New(limit int, period time.Duration) *Limiter {
	return &Limiter{m: make(map[string]*window), limit: limit, period: period}
}

// Allow 消费一次配额并返回是否放行。
func (l *Limiter) Allow(key string) bool {
	if l == nil || l.limit <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	w, ok := l.m[key]
	if !ok || now.After(w.reset) {
		l.m[key] = &window{count: 1, reset: now.Add(l.period)}
		return true
	}
	if w.count >= l.limit {
		return false
	}
	w.count++
	return true
}

// RetryAfter 返回该键当前窗口的剩余时间；无记录时返回 0。
func (l *Limiter) RetryAfter(key string) time.Duration {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	w, ok := l.m[key]
	if !ok {
		return 0
	}
	if d := time.Until(w.reset); d > 0 {
		return d
	}
	return 0
}

// Cleanup 清理已过期的窗口，避免 map 无限增长。应周期性调用。
func (l *Limiter) Cleanup() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	for k, w := range l.m {
		if now.After(w.reset) {
			delete(l.m, k)
		}
	}
}

type failState struct {
	fails    int
	lockedTo time.Time
	seen     time.Time
}

// FailLocker 按键（通常为账号）累计失败次数，达到阈值后临时锁定。
type FailLocker struct {
	mu       sync.Mutex
	m        map[string]*failState
	max      int
	lockFor  time.Duration
	idleKeep time.Duration
}

// NewFailLocker 创建失败锁定器：累计 max 次失败后锁定 lockFor 时长。
func NewFailLocker(max int, lockFor time.Duration) *FailLocker {
	return &FailLocker{
		m:        make(map[string]*failState),
		max:      max,
		lockFor:  lockFor,
		idleKeep: 24 * time.Hour,
	}
}

// Locked 返回该键当前是否处于锁定期。
func (f *FailLocker) Locked(key string) bool {
	if f == nil || f.max <= 0 {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	st, ok := f.m[key]
	if !ok {
		return false
	}
	if time.Now().Before(st.lockedTo) {
		return true
	}
	return false
}

// Fail 记录一次失败；达到阈值则进入锁定期。
func (f *FailLocker) Fail(key string) {
	if f == nil || f.max <= 0 {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	st, ok := f.m[key]
	if !ok {
		st = &failState{}
		f.m[key] = st
	}
	st.fails++
	st.seen = now
	if st.fails >= f.max {
		st.lockedTo = now.Add(f.lockFor)
		st.fails = 0
	}
}

// Reset 清除该键的失败与锁定状态（登录成功时调用）。
func (f *FailLocker) Reset(key string) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.m, key)
}

// Cleanup 清理长期未活动且未锁定的记录。
func (f *FailLocker) Cleanup() {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	for k, st := range f.m {
		if now.Before(st.lockedTo) {
			continue
		}
		if now.Sub(st.seen) > f.idleKeep {
			delete(f.m, k)
		}
	}
}
