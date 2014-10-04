// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/

package hawk

import (
	"time"
)

type ReplayChecker interface {
	Remember(id string) error
	Check(id string) (bool, error)
}

type MemoryBackedReplayChecker struct {
	ids map[string]time.Time
}

func NewMemoryBackedReplayChecker() *MemoryBackedReplayChecker {
	return &MemoryBackedReplayChecker{
		ids: map[string]time.Time{},
	}
}

func (rc *MemoryBackedReplayChecker) Remember(id string) error {
	rc.ids[id] = time.Now()
	return nil
}

func (rc *MemoryBackedReplayChecker) Check(id string) (bool, error) {
	_, ok := rc.ids[id]
	return ok, nil
}
