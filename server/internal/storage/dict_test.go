package storage

import (
	"context"
	"errors"
	"sync"
	"testing"
)

func TestLRUGetPutEvict(t *testing.T) {
	c := newLRU(3)
	c.put("a", 1)
	c.put("b", 2)
	c.put("c", 3)
	// Touch "a" so it is most-recently used.
	if v, ok := c.get("a"); !ok || v != 1 {
		t.Fatalf("get a = %d, %v", v, ok)
	}
	c.put("d", 4) // evicts "b" (least recently used)
	if _, ok := c.get("b"); ok {
		t.Fatal("b should have been evicted")
	}
	for _, k := range []string{"a", "c", "d"} {
		if _, ok := c.get(k); !ok {
			t.Fatalf("%s should still be present", k)
		}
	}
}

func TestDictSingleFlightsMisses(t *testing.T) {
	d := &dict{cache: newLRU(10)}
	const want int64 = 42
	var mu sync.Mutex
	calls := 0
	miss := func(context.Context) (int64, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		return want, nil
	}

	var wg sync.WaitGroup
	ids := make([]int64, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id, err := d.resolve(context.Background(), "same-key", miss)
			if err != nil {
				t.Errorf("resolve: %v", err)
			}
			ids[i] = id
		}(i)
	}
	wg.Wait()

	if calls != 1 {
		t.Fatalf("miss called %d times, want 1", calls)
	}
	for _, id := range ids {
		if id != want {
			t.Fatalf("id = %d, want %d", id, want)
		}
	}
}

func TestDictMissErrorNotCached(t *testing.T) {
	d := &dict{cache: newLRU(10)}
	boom := errors.New("boom")
	_, err := d.resolve(context.Background(), "k", func(context.Context) (int64, error) { return 0, boom })
	if err == nil {
		t.Fatal("expected error")
	}
	// A second call should retry the miss.
	if _, ok := d.cache.get("k"); ok {
		t.Fatal("error result must not be cached")
	}
}

func TestNormalizeHostID(t *testing.T) {
	// A valid UUID is returned unchanged (normalized).
	const id = "11111111-2222-3333-4444-555555555555"
	if got := NormalizeHostID(id); got != id {
		t.Fatalf("got %s, want %s", got, id)
	}
	// A non-UUID is deterministically mapped.
	a := NormalizeHostID("web-01")
	b := NormalizeHostID("web-01")
	if a != b {
		t.Fatalf("non-deterministic mapping: %s vs %s", a, b)
	}
	if a == "web-01" {
		t.Fatal("non-UUID should be mapped to a UUID")
	}
	// Distinct inputs map to distinct UUIDs.
	if NormalizeHostID("web-01") == NormalizeHostID("web-02") {
		t.Fatal("distinct inputs collided")
	}
}
