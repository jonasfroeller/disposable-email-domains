package storage

import (
	"errors"
	"sort"
	"sync"
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

func newID() string {
	return time.Now().UTC().Format("20060102T150405.000000000Z07:00")
}
