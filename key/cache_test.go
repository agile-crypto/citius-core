package key

import "testing"

func TestLRUCacheGet(t *testing.T) {
	c := newLRUCache[string, int](2)
	c.put("a", 1)
	v, ok := c.get("a")
	if !ok || v != 1 {
		t.Fatalf("expected (1, true), got (%d, %v)", v, ok)
	}
}

func TestLRUCacheGetMissing(t *testing.T) {
	c := newLRUCache[string, int](2)
	_, ok := c.get("missing")
	if ok {
		t.Fatal("expected false for missing key")
	}
}

func TestLRUCachePutOverwrites(t *testing.T) {
	c := newLRUCache[string, int](2)
	c.put("a", 1)
	c.put("a", 99)
	v, ok := c.get("a")
	if !ok || v != 99 {
		t.Fatalf("expected (99, true), got (%d, %v)", v, ok)
	}
}

func TestLRUCacheRemove(t *testing.T) {
	c := newLRUCache[string, int](2)
	c.put("a", 1)
	c.remove("a")
	_, ok := c.get("a")
	if ok {
		t.Fatal("expected false for removed key")
	}
}

func TestLRUCacheRemoveIsNoOpWhenMissing(t *testing.T) {
	c := newLRUCache[string, int](2)
	c.put("a", 1)
	c.remove("missing") // should not panic or affect existing keys
	v, ok := c.get("a")
	if !ok || v != 1 {
		t.Fatalf("expected (1, true), got (%d, %v)", v, ok)
	}
}

func TestLRUCacheEviction(t *testing.T) {
	cases := []struct {
		name    string
		ops     func(c *lruCache[string, int])
		evicted string
		kept    string
	}{
		{
			name: "evicts least recently put",
			ops: func(c *lruCache[string, int]) {
				c.put("a", 1)
				c.put("b", 2)
			},
			evicted: "a",
			kept:    "b",
		},
		{
			name: "get refreshes recency, older untouched key is evicted",
			ops: func(c *lruCache[string, int]) {
				c.put("a", 1)
				c.put("b", 2)
				c.get("a") // "a" is now most recent; "b" becomes LRU
			},
			evicted: "b",
			kept:    "a",
		},
		{
			name: "put on existing key refreshes recency",
			ops: func(c *lruCache[string, int]) {
				c.put("a", 1)
				c.put("b", 2)
				c.put("a", 10) // "a" refreshed; "b" becomes LRU
			},
			evicted: "b",
			kept:    "a",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newLRUCache[string, int](2)
			tc.ops(c)
			c.put("c", 3) // triggers eviction

			if _, ok := c.get(tc.evicted); ok {
				t.Errorf("expected key %q to be evicted", tc.evicted)
			}
			if _, ok := c.get(tc.kept); !ok {
				t.Errorf("expected key %q to still be present", tc.kept)
			}
		})
	}
}
