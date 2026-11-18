package key

import "container/list"

type cache[T comparable, V any] interface {
	// Get returns the value for the given key, and whether it was found in the cache.
	get(T) (V, bool)
	put(T, V)
	remove(T)
}

type cacheEntry[T comparable, V any] struct {
	key   T
	value V
}

// lruCache is a simple LRU cache implementation using a map for O(1) lookups and a linked list to track usage order.
type lruCache[T comparable, V any] struct {
	capacity int
	items    map[T]*list.Element
	order    *list.List
}

var _ cache[string, any] = (*lruCache[string, any])(nil)

func newLRUCache[T comparable, V any](capacity int) *lruCache[T, V] {
	return &lruCache[T, V]{
		capacity: capacity,
		items:    make(map[T]*list.Element, capacity),
		order:    list.New(),
	}
}

func (c *lruCache[T, V]) get(key T) (V, bool) {
	el, ok := c.items[key]
	if !ok {
		var zero V
		return zero, false
	}
	c.order.MoveToFront(el)
	entry := el.Value.(*cacheEntry[T, V])
	return entry.value, true
}

func (c *lruCache[T, V]) put(key T, value V) {
	if el, ok := c.items[key]; ok {
		el.Value = &cacheEntry[T, V]{key: key, value: value}
		c.order.MoveToFront(el)
		return
	}
	if c.order.Len() >= c.capacity {
		oldest := c.order.Back()
		if oldest != nil {
			c.order.Remove(oldest)
			entry := oldest.Value.(*cacheEntry[T, V])
			delete(c.items, entry.key)
		}
	}
	el := c.order.PushFront(&cacheEntry[T, V]{key: key, value: value})
	c.items[key] = el
}

func (c *lruCache[T, V]) remove(key T) {
	if el, ok := c.items[key]; ok {
		c.order.Remove(el)
		delete(c.items, key)
	}
}
