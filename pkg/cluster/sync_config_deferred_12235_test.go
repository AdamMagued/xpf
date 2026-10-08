package cluster

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

func TestConfigApplyPendingWaitsBeforeHighWaterAndAck12235(t *testing.T) {
	for _, tc := range []struct {
		name       string
		completion error
		wantAck    bool
		wantNack   bool
	}{
		{name: "landed", wantAck: true},
		{name: "refused", completion: errors.New("helper refused deferred publish"), wantNack: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const gen = uint64(84)
			s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
			conn := &captureConn{}
			s.mu.Lock()
			s.conn0 = conn
			s.mu.Unlock()
			started := make(chan struct{}, 1)
			completion := make(chan error, 1)
			s.OnConfigReceived = func(string) error {
				started <- struct{}{}
				return &ConfigApplyPendingError{Completion: completion}
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() {
				defer close(done)
				s.configApplyLoop(ctx)
			}()
			s.configApplyCh <- configApplyItem{gen: gen, text: "set system host-name deferred", conn: conn}
			select {
			case <-started:
			case <-time.After(2 * time.Second):
				cancel()
				t.Fatal("deferred apply callback did not run")
			}
			if got := s.lastAppliedConfigGen.Load(); got != 0 {
				cancel()
				t.Fatalf("deferred generation advanced high-water before publication: %d", got)
			}
			if got := s.applyingConfigGen.Load(); got != gen {
				cancel()
				t.Fatalf("deferred generation fence = %d, want %d until publication", got, gen)
			}
			if hasConfigFrame12235(conn, syncMsgConfigApplyAck, gen) ||
				hasConfigFrame12235(conn, syncMsgConfigApplyNack, gen) {
				cancel()
				t.Fatal("deferred generation received an HA result before publication")
			}

			completion <- tc.completion
			wantType := uint8(syncMsgConfigApplyAck)
			if tc.wantNack {
				wantType = syncMsgConfigApplyNack
			}
			if !waitForConfigFrame12235(conn, wantType, gen) {
				cancel()
				t.Fatalf("deferred completion emitted no frame type %d for generation %d", wantType, gen)
			}
			if tc.wantNack && hasConfigFrame12235(conn, syncMsgConfigApplyAck, gen) {
				cancel()
				t.Fatal("refused deferred generation was also ACKed")
			}
			if tc.wantAck {
				if got := s.lastAppliedConfigGen.Load(); got != gen {
					cancel()
					t.Fatalf("landed generation high-water = %d, want %d", got, gen)
				}
			} else if got := s.lastAppliedConfigGen.Load(); got != 0 {
				cancel()
				t.Fatalf("refused generation advanced high-water to %d", got)
			}
			cancel()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("config apply loop did not stop")
			}
		})
	}
}

func hasConfigFrame12235(conn *captureConn, msgType uint8, gen uint64) bool {
	for _, frame := range conn.frames() {
		if frame.msgType == msgType && len(frame.payload) >= 8 &&
			binary.LittleEndian.Uint64(frame.payload[:8]) == gen {
			return true
		}
	}
	return false
}

func waitForConfigFrame12235(conn *captureConn, msgType uint8, gen uint64) bool {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if hasConfigFrame12235(conn, msgType, gen) {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return false
}

func TestConfigApplyPendingTimeoutNacks12235(t *testing.T) {
	const gen = uint64(85)
	s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	s.configApplyFailGrace = 10 * time.Millisecond
	s.afterFuncFn = (&fakeAfterFunc{}).schedule
	conn := &captureConn{}
	s.mu.Lock()
	s.conn0 = conn
	s.mu.Unlock()
	started := make(chan struct{}, 1)
	s.OnConfigReceived = func(string) error {
		started <- struct{}{}
		return &ConfigApplyPendingError{Completion: make(chan error)}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.configApplyLoop(ctx)
		close(done)
	}()
	s.configApplyCh <- configApplyItem{gen: gen, text: "set system host-name timeout", conn: conn}
	select {
	case <-started:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("config apply handler did not start")
	}
	if !waitForConfigFrame12235(conn, syncMsgConfigApplyNack, gen) {
		cancel()
		t.Fatal("deferred publication timeout did not NACK the config generation")
	}
	if hasConfigFrame12235(conn, syncMsgConfigApplyAck, gen) {
		cancel()
		t.Fatal("timed-out deferred publication also ACKed the config generation")
	}
	if got := s.lastAppliedConfigGen.Load(); got != 0 {
		cancel()
		t.Fatalf("timed-out generation advanced high-water to %d, want 0", got)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("config apply loop did not stop")
	}
}

func TestConfigApplyPendingDropsReplacedIncarnation12235(t *testing.T) {
	const gen = uint64(86)
	s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	oldIncarnation := bootIncarnation{0x12}
	newIncarnation := bootIncarnation{0x34}
	s.notePeerBootIncarnation(oldIncarnation)
	conn := &captureConn{}
	s.mu.Lock()
	s.conn0 = conn
	s.mu.Unlock()
	started := make(chan struct{}, 1)
	completion := make(chan error, 1)
	s.OnConfigReceived = func(string) error {
		started <- struct{}{}
		return &ConfigApplyPendingError{Completion: completion}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.configApplyLoop(ctx)
		close(done)
	}()
	s.configApplyCh <- configApplyItem{
		gen: gen, text: "set system host-name rebooted", incarnation: oldIncarnation, conn: conn,
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("config apply handler did not start")
	}
	if !s.notePeerBootIncarnation(newIncarnation) {
		cancel()
		t.Fatal("test setup did not replace the peer boot incarnation")
	}
	completion <- nil
	deadline := time.Now().Add(time.Second)
	for s.stats.ConfigsDeadIncarnationDropped.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := s.stats.ConfigsDeadIncarnationDropped.Load(); got != 1 {
		cancel()
		t.Fatalf("dead-incarnation drop count = %d, want 1", got)
	}
	if got := s.lastAppliedConfigGen.Load(); got != 0 {
		cancel()
		t.Fatalf("old-incarnation generation advanced high-water to %d", got)
	}
	if hasConfigFrame12235(conn, syncMsgConfigApplyAck, gen) ||
		hasConfigFrame12235(conn, syncMsgConfigApplyNack, gen) {
		cancel()
		t.Fatal("old-incarnation generation received an ACK or NACK after the wait")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("config apply loop did not stop")
	}
}
