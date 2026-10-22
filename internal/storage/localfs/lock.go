package localfs

import "sync"

// keyLocks hands out one read-write lock per key. Entries are reference counted and dropped
// when nobody holds or waits for them, so the table does not grow with the number of keys.
type keyLocks struct {
	mu      sync.Mutex
	entries map[string]*lockEntry
}

type lockEntry struct {
	rw   sync.RWMutex
	refs int
}

func newKeyLocks() *keyLocks {
	return &keyLocks{entries: make(map[string]*lockEntry)}
}

// lock takes the write lock for key and returns its release function.
func (l *keyLocks) lock(key string) func() {
	e := l.acquire(key)
	e.rw.Lock()
	return func() {
		e.rw.Unlock()
		l.release(key, e)
	}
}

// rlock takes the read lock for key and returns its release function.
func (l *keyLocks) rlock(key string) func() {
	e := l.acquire(key)
	e.rw.RLock()
	return func() {
		e.rw.RUnlock()
		l.release(key, e)
	}
}

func (l *keyLocks) acquire(key string) *lockEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[key]
	if !ok {
		e = &lockEntry{}
		l.entries[key] = e
	}
	e.refs++
	return e
}

func (l *keyLocks) release(key string, e *lockEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e.refs--
	if e.refs == 0 {
		delete(l.entries, key)
	}
}
