package dedupe

import (
	"sync"
	"time"
)

// Key identifies a connect flow for coalescing.
type Key struct {
	PID     uint32
	Dst     string
	Dport   uint16
	Proto   uint8
	Allowed uint8
	Kind    uint8
}

// Cache suppresses duplicate keys for TTL.
type Cache struct {
	mu   sync.Mutex
	ttl  time.Duration
	seen map[Key]time.Time
}

func New(ttl time.Duration) *Cache {
	if ttl <= 0 {
		ttl = 5 * time.Second
	}
	return &Cache{ttl: ttl, seen: make(map[Key]time.Time)}
}

// ShouldEmit returns true if this key has not been seen within TTL.
func (c *Cache) ShouldEmit(k Key) bool {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if t, ok := c.seen[k]; ok && now.Sub(t) < c.ttl {
		return false
	}
	c.seen[k] = now
	if len(c.seen) > 10000 {
		c.gcLocked(now)
	}
	return true
}

func (c *Cache) gcLocked(now time.Time) {
	for k, t := range c.seen {
		if now.Sub(t) >= c.ttl {
			delete(c.seen, k)
		}
	}
}
