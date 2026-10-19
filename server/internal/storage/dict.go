package storage

import (
	"container/list"
	"context"
	"sync"
)

// DefaultDictCacheSize is the LRU capacity for dictionary ID caches (spec:
// 5,000 items each).
const DefaultDictCacheSize = 5000

// lru is a minimal thread-safe LRU cache mapping string keys to int64 IDs.
type lru struct {
	mu  sync.Mutex
	cap int
	ll  *list.List
	m   map[string]*list.Element
}

type lruEntry struct {
	key string
	val int64
}

func newLRU(cap int) *lru {
	if cap <= 0 {
		cap = DefaultDictCacheSize
	}
	return &lru{cap: cap, ll: list.New(), m: make(map[string]*list.Element, cap)}
}

func (c *lru) get(key string) (int64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.m[key]; ok {
		c.ll.MoveToFront(e)
		return e.Value.(*lruEntry).val, true
	}
	return 0, false
}

func (c *lru) put(key string, val int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.m[key]; ok {
		e.Value.(*lruEntry).val = val
		c.ll.MoveToFront(e)
		return
	}
	e := c.ll.PushFront(&lruEntry{key: key, val: val})
	c.m[key] = e
	if c.ll.Len() > c.cap {
		if oldest := c.ll.Back(); oldest != nil {
			c.ll.Remove(oldest)
			delete(c.m, oldest.Value.(*lruEntry).key)
		}
	}
}

// dict resolves repeated strings to their dictionary row IDs, caching hits
// in an LRU and single-flighting misses so concurrent ingests of the same
// value issue only one upsert.
type dict struct {
	cache *lru
	mu    sync.Mutex
}

func (d *dict) resolve(ctx context.Context, key string, miss func(context.Context) (int64, error)) (int64, error) {
	if v, ok := d.cache.get(key); ok {
		return v, nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if v, ok := d.cache.get(key); ok {
		return v, nil
	}
	id, err := miss(ctx)
	if err != nil {
		return 0, err
	}
	d.cache.put(key, id)
	return id, nil
}
