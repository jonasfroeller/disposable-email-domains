package storage

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"disposable-email-domains/internal/handlers"
)

type MemoryStore struct {
	mu    sync.RWMutex
	items map[string]handlers.Item
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{items: make(map[string]handlers.Item)}
}

func (s *MemoryStore) List() []handlers.Item {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]handlers.Item, 0, len(s.items))
	for _, v := range s.items {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

func (s *MemoryStore) Get(id string) (handlers.Item, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.items[id]
	return v, ok
}

func (s *MemoryStore) Create(name string) (handlers.Item, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := newID()
	item := handlers.Item{ID: id, Name: name, CreatedAt: time.Now().UTC()}
	s.items[id] = item
	return item, nil
}

func (s *MemoryStore) Update(id, name string) (handlers.Item, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.items[id]
	if !ok {
		return handlers.Item{}, errors.New("not found")
	}
	old.Name = name
	s.items[id] = old
	return old, nil
}

func (s *MemoryStore) Delete(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.items[id]; !ok {
		return false
	}
	delete(s.items, id)
	return true
}

var idSeq atomic.Uint64

func newID() string {
	// 8 bytes timestamp (unix nanos), 4 bytes counter, 4 bytes random = 16 bytes -> 32 hex chars
	buf := make([]byte, 16)
	ts := time.Now().UnixNano()
	for i := 0; i < 8; i++ { // big-endian timestamp
		buf[7-i] = byte(ts)
		ts >>= 8
	}
	c := idSeq.Add(1)
	buf[8] = byte(c >> 24)
	buf[9] = byte(c >> 16)
	buf[10] = byte(c >> 8)
	buf[11] = byte(c)
	// random suffix
	if _, err := rand.Read(buf[12:]); err != nil {
		// fallback to time-derived bytes
		t := time.Now().UnixNano()
		buf[12] = byte(t)
		buf[13] = byte(t >> 8)
		buf[14] = byte(t >> 16)
		buf[15] = byte(t >> 24)
	}
	dst := make([]byte, hex.EncodedLen(len(buf)))
	hex.Encode(dst, buf)
	return string(dst)
}
