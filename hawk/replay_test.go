// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/

package hawk

import (
	"testing"
	"time"
)

func Test_ReplaySeen(t *testing.T) {
	checker := NewMemoryBackedReplayChecker()
	if err := checker.Remember("xxx"); err != nil {
		t.Error("Can't remember a request")
	}
	seen, err := checker.Check("xxx")
	if err != nil {
		t.Error("Can't check a request")
	}
	if seen != true {
		t.Error("seen != true")
	}
}

func Test_ReplaySeenExpired(t *testing.T) {
	checker := NewMemoryBackedReplayChecker()
	checker.ttl = 1 * time.Second
	if err := checker.Remember("xxx"); err != nil {
		t.Error("Can't remember a request")
	}

	seen, err := checker.Check("xxx")
	if err != nil {
		t.Error("Can't check a request")
	}
	if seen != true {
		t.Error("seen != true - before expiration")
	}

	time.Sleep(2 * time.Second)

	seen, err = checker.Check("xxx")
	if err != nil {
		t.Error("Can't check a request")
	}
	if seen != false {
		t.Error("seen != false - after expiration")
	}
}

func Test_ReplayNotSeen(t *testing.T) {
	checker := NewMemoryBackedReplayChecker()
	seen, err := checker.Check("someuniquerequestid")
	if err != nil {
		t.Error("Can't check a request")
	}
	if seen != false {
		t.Error("seen != false")
	}
}
