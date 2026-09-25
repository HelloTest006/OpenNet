// Package store keeps content-addressed blocks. Mem is the milestone-1
// store: everything in memory, guarded by one mutex. The .opennet container
// replaces it as the durable backend; callers only ever see Store.
package store

import (
	"errors"
	"sync"

	"opennet/internal/cid"
)

var ErrNotFound = errors.New("store: block not found")

type Store interface {
	Put(data []byte) cid.ID
	Get(id cid.ID) ([]byte, error)
	Has(id cid.ID) bool
	IDs() []cid.ID
}

type Mem struct {
	mu     sync.RWMutex
	blocks map[cid.ID][]byte
}

func NewMem() *Mem { return &Mem{blocks: map[cid.ID][]byte{}} }

// Put stores data and returns its CID. Identical bytes land once.
func (m *Mem) Put(data []byte) cid.ID {
	id := cid.Sum(data)
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.blocks[id]; !ok {
		stored := make([]byte, len(data))
		copy(stored, data)
		m.blocks[id] = stored
	}
	return id
}

func (m *Mem) Get(id cid.ID) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, ok := m.blocks[id]
	if !ok {
		return nil, ErrNotFound
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out, nil
}

func (m *Mem) Has(id cid.ID) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.blocks[id]
	return ok
}

func (m *Mem) IDs() []cid.ID {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]cid.ID, 0, len(m.blocks))
	for id := range m.blocks {
		out = append(out, id)
	}
	return out
}
