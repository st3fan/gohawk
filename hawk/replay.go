// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/

package hawk

import (
	"sync"
	"time"
)

type ReplayChecker interface {
	Remember(id string) error
	Check(id string) (bool, error)
}

// MemoryBackedReplayChecker

type replayCacheItem struct {
	expires time.Time
}

func (i *replayCacheItem) expired() bool {
	return time.Now().After(i.expires)
}

type MemoryBackedReplayChecker struct {
	lock  sync.RWMutex
	ttl   time.Duration
	items map[string]*replayCacheItem
}

func NewMemoryBackedReplayChecker() *MemoryBackedReplayChecker {
	return &MemoryBackedReplayChecker{
		ttl:   10 * time.Second,
		items: map[string]*replayCacheItem{},
	}
}

func (rc *MemoryBackedReplayChecker) Remember(id string) error {
	rc.lock.Lock()
	defer rc.lock.Unlock()
	rc.items[id] = &replayCacheItem{expires: time.Now().Add(rc.ttl)}
	return nil
}

func (rc *MemoryBackedReplayChecker) Check(id string) (bool, error) {
	rc.lock.RLock()
	defer rc.lock.RUnlock()
	item, found := rc.items[id]
	if !found {
		return false, nil
	} else {
		return !item.expired(), nil
	}
}

func (rc *MemoryBackedReplayChecker) expire() {
	rc.lock.Lock()
	defer rc.lock.Unlock()
	for key, item := range rc.items {
		if item.expired() {
			delete(rc.items, key)
		}
	}
}
