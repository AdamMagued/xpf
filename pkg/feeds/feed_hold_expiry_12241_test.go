package feeds

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestHoldExpiryUsesWallClock12241 scales the issue's 300s hold / 3600s
// refresh cadence by 1/1000, preserving their ratio while keeping the test
// bounded. An upstream outage begins on the initial fetch at T0; the snapshot
// must drop at the hold deadline without another fetch failure.
func TestHoldExpiryUsesWallClock12241(t *testing.T) {
	var requests, updates atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "upstream unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	m := New(func() error {
		updates.Add(1)
		return nil
	})
	const hold = 300 * time.Millisecond      // represents the issue's 300s hold
	const interval = 3600 * time.Millisecond // represents the 3600s fetch cadence
	fs := m.newFeed("hold-expiry", server.URL, hold)
	m.mu.Lock()
	fs.prefixes = []string{"192.0.2.0/24"}
	fs.hasSnapshot = true
	m.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	fs.done = done
	go m.refreshLoop(ctx, fs, interval)
	defer func() {
		cancel()
		<-done
	}()

	// The initial fetch is the sole failed fetch. Observe the T0 failure marker
	// so the bound below measures from the actual first failure.
	var staleSince time.Time
	deadline := time.Now().Add(2 * time.Second)
	for staleSince.IsZero() && time.Now().Before(deadline) {
		m.mu.RLock()
		staleSince = fs.staleSince
		m.mu.RUnlock()
		time.Sleep(time.Millisecond)
	}
	if staleSince.IsZero() {
		t.Fatal("initial failed fetch did not mark the installed snapshot stale")
	}

	// Allow a scheduling epsilon after the hold deadline, but still require the
	// drop far ahead of the next fetch and reject a 2x-hold late drop.
	// No second failure is injected.
	var droppedAt time.Time
	expiryDeadline := staleSince.Add(hold).Add(250 * time.Millisecond)
	for time.Now().Before(expiryDeadline) {
		m.mu.RLock()
		dropped := fs.holdDropped
		m.mu.RUnlock()
		if dropped && updates.Load() == 1 {
			droppedAt = time.Now()
			break
		}
		time.Sleep(time.Millisecond)
	}

	m.mu.RLock()
	dropped := fs.holdDropped
	hasSnapshot := fs.hasSnapshot
	m.mu.RUnlock()
	if !dropped || hasSnapshot || len(m.GetPrefixes("hold-expiry")) != 0 {
		t.Fatalf("snapshot not dropped by wall-clock hold deadline: dropped=%v hasSnapshot=%v prefixes=%v; requests=%d",
			dropped, hasSnapshot, m.GetPrefixes("hold-expiry"), requests.Load())
	}
	if early := droppedAt.Sub(staleSince); early < hold {
		t.Fatalf("snapshot dropped %v after staleSince, before the %v hold (premature fail-open)", early, hold)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("requests=%d, want exactly one failed fetch before the 3600s cadence", got)
	}
	if got := updates.Load(); got != 1 {
		t.Fatalf("onUpdate calls=%d, want one publication for the time-triggered drop", got)
	}
}

// TestHoldExpiryAfterPeriodicFailure12241 covers the production-common case:
// the feed is healthy at boot and the outage begins on a periodic fetch.
// The refresh loop must re-arm the hold timer after that failed tick so the
// stale snapshot still drops at the hold deadline, not at the next fetch.
func TestHoldExpiryAfterPeriodicFailure12241(t *testing.T) {
	var requests, updates atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			_, _ = w.Write([]byte("192.0.2.0/24\n"))
			return
		}
		http.Error(w, "upstream unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	m := New(func() error { updates.Add(1); return nil })
	const hold = 300 * time.Millisecond
	const interval = 1500 * time.Millisecond
	fs := m.newFeed("tick-hold", server.URL, hold)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	fs.done = done
	go m.refreshLoop(ctx, fs, interval)
	defer func() { cancel(); <-done }()
	var staleSince time.Time
	deadline := time.Now().Add(interval + 2*time.Second)
	for staleSince.IsZero() && time.Now().Before(deadline) {
		m.mu.RLock()
		staleSince = fs.staleSince
		m.mu.RUnlock()
		time.Sleep(time.Millisecond)
	}
	if staleSince.IsZero() {
		t.Fatal("periodic failed fetch did not mark the installed snapshot stale")
	}
	var droppedAt time.Time
	expiryDeadline := staleSince.Add(hold).Add(250 * time.Millisecond)
	for time.Now().Before(expiryDeadline) {
		m.mu.RLock()
		dropped := fs.holdDropped
		m.mu.RUnlock()
		if dropped {
			droppedAt = time.Now()
			break
		}
		time.Sleep(time.Millisecond)
	}
	if droppedAt.IsZero() {
		t.Fatalf("tick-path stale snapshot not dropped by hold deadline: requests=%d prefixes=%v", requests.Load(), m.GetPrefixes("tick-hold"))
	}
	if early := droppedAt.Sub(staleSince); early < hold {
		t.Fatalf("snapshot dropped %v after staleSince, before the %v hold (premature fail-open)", early, hold)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("requests=%d, want 2", got)
	}
	for updates.Load() < 2 && time.Now().Before(expiryDeadline) {
		time.Sleep(time.Millisecond)
	}
	if got := updates.Load(); got != 2 {
		t.Fatalf("onUpdate calls=%d, want 2", got)
	}
}
