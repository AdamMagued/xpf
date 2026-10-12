package grpcapi

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/diagcmd"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const cursorCancelTestRows12180 = 20 * sessionWalkCancelInterval9060

type cursorCancelDP12180 struct {
	*dataplane.Manager
	nV4, nV6                         int
	countV4Rows, countV6Rows         int
	cursorV4Visited                  int
	cursorV6Visited                  int
	countV4Calls, countV4Visited     int
	countV6Calls, countV6Visited     int
	sessionCountCalls                int
	cursorV6Calls                    int
	cancel                           context.CancelFunc
	cancelAtV4, cancelAtV6           int
	cancelAtCountV4, cancelAtCountV6 int
}

func (d *cursorCancelDP12180) IsLoaded() bool { return true }

func (d *cursorCancelDP12180) IterateSessionsFrom(_ *dataplane.SessionKey, fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	for range d.nV4 {
		d.cursorV4Visited++
		if d.cancel != nil && d.cursorV4Visited == d.cancelAtV4 {
			d.cancel()
		}
		key := dataplane.SessionKey{Protocol: 6}
		if !fn(key, dataplane.SessionValue{}) {
			return nil
		}
	}
	return nil
}

func (d *cursorCancelDP12180) IterateSessionsV6From(_ *dataplane.SessionKeyV6, fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	d.cursorV6Calls++
	for range d.nV6 {
		d.cursorV6Visited++
		if d.cancel != nil && d.cursorV6Visited == d.cancelAtV6 {
			d.cancel()
		}
		key := dataplane.SessionKeyV6{Protocol: 6}
		if !fn(key, dataplane.SessionValueV6{}) {
			return nil
		}
	}
	return nil
}

// SessionCount models the old uninterruptible v4+v6 map walk so the
// unfiltered-total regression detects a return to that path.
func (d *cursorCancelDP12180) SessionCount() (v4, v6 int) {
	d.sessionCountCalls++
	for range d.countV4Rows {
		d.countV4Visited++
		if d.cancel != nil && d.countV4Visited == d.cancelAtCountV4 {
			d.cancel()
		}
		v4++
	}
	d.countV6Calls++
	for range d.countV6Rows {
		d.countV6Visited++
		if d.cancel != nil && d.countV6Visited == d.cancelAtCountV6 {
			d.cancel()
		}
		v6++
	}
	return v4, v6
}

func (d *cursorCancelDP12180) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	d.countV4Calls++
	for range d.countV4Rows {
		d.countV4Visited++
		if d.cancel != nil && d.countV4Visited == d.cancelAtCountV4 {
			d.cancel()
		}
		if !fn(dataplane.SessionKey{Protocol: 6}, dataplane.SessionValue{}) {
			return nil
		}
	}
	return nil
}

func (d *cursorCancelDP12180) IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	d.countV6Calls++
	for range d.countV6Rows {
		d.countV6Visited++
		if d.cancel != nil && d.countV6Visited == d.cancelAtCountV6 {
			d.cancel()
		}
		if !fn(dataplane.SessionKeyV6{Protocol: 6}, dataplane.SessionValueV6{}) {
			return nil
		}
	}
	return nil
}

func withSingleSessionWalkSlot12180(t *testing.T) {
	t.Helper()
	original := sessionWalkLimiter
	sessionWalkLimiter = diagcmd.NewLimiter(1)
	t.Cleanup(func() { sessionWalkLimiter = original })
}

func assertCancelledAndReleased12180(t *testing.T, err error) {
	t.Helper()
	if status.Code(err) != codes.Canceled {
		t.Fatalf("GetSessions error = %v (code %v), want Canceled", err, status.Code(err))
	}
	if got := sessionWalkLimiter.InFlight(); got != 0 {
		t.Fatalf("cancelled GetSessions left %d walk slots in flight, want 0", got)
	}
	release, acquireErr := sessionWalkLimiter.Acquire()
	if acquireErr != nil {
		t.Fatalf("walk slot unavailable after cancellation: %v", acquireErr)
	}
	release()
}

func TestGetSessionsCursorCancelsDuringV4Walk12180(t *testing.T) {
	withSingleSessionWalkSlot12180(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dp := &cursorCancelDP12180{
		Manager: dataplane.New(), nV4: cursorCancelTestRows12180, nV6: 1,
		cancel: cancel, cancelAtV4: sessionWalkCancelInterval9060 / 2,
	}
	s := newViewServer(t, dp)

	_, err := s.GetSessions(ctx, &pb.GetSessionsRequest{Protocol: "udp", PageSize: 1})

	if dp.cursorV4Visited > sessionWalkCancelInterval9060 {
		t.Errorf("selective cursor visited %d of %d v4 rows after cancellation, want at most %d", dp.cursorV4Visited, dp.nV4, sessionWalkCancelInterval9060)
	}
	if dp.cursorV6Calls != 0 {
		t.Errorf("v6 cursor started %d times after v4 cancellation, want 0", dp.cursorV6Calls)
	}
	if dp.countV4Calls != 0 || dp.countV6Calls != 0 {
		t.Errorf("filtered total ran after page-walk cancellation: v4 calls=%d, v6 walks=%d", dp.countV4Calls, dp.countV6Calls)
	}
	assertCancelledAndReleased12180(t, err)
}

func TestGetSessionsCursorCancelsDuringV6Walk12180(t *testing.T) {
	withSingleSessionWalkSlot12180(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dp := &cursorCancelDP12180{
		Manager: dataplane.New(), nV6: cursorCancelTestRows12180,
		cancel: cancel, cancelAtV6: sessionWalkCancelInterval9060 / 2,
	}
	s := newViewServer(t, dp)

	_, err := s.GetSessions(ctx, &pb.GetSessionsRequest{
		Protocol: "udp", PageSize: 1, PageToken: encodePageTokenV6Start(),
	})

	if dp.cursorV6Visited > sessionWalkCancelInterval9060 {
		t.Errorf("selective cursor visited %d of %d v6 rows after cancellation, want at most %d", dp.cursorV6Visited, dp.nV6, sessionWalkCancelInterval9060)
	}
	if dp.countV4Calls != 0 || dp.countV6Calls != 0 {
		t.Errorf("filtered total ran after page-walk cancellation: v4 calls=%d, v6 walks=%d", dp.countV4Calls, dp.countV6Calls)
	}
	assertCancelledAndReleased12180(t, err)
}

func TestGetSessionsFilteredTotalCancelsBeforeV6Count12180(t *testing.T) {
	withSingleSessionWalkSlot12180(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dp := &cursorCancelDP12180{
		Manager: dataplane.New(), nV4: 1, nV6: 1,
		countV4Rows: cursorCancelTestRows12180,
		cancel:      cancel, cancelAtCountV4: sessionWalkCancelInterval9060 / 2,
	}
	s := newViewServer(t, dp)

	_, err := s.GetSessions(ctx, &pb.GetSessionsRequest{Protocol: "udp", PageSize: 1})

	if dp.countV4Calls != 1 {
		t.Errorf("filtered total called v4 iterator %d times, want 1", dp.countV4Calls)
	}
	if dp.countV4Visited > sessionWalkCancelInterval9060 {
		t.Errorf("filtered total visited %d v4 rows after cancellation, want at most %d", dp.countV4Visited, sessionWalkCancelInterval9060)
	}
	if dp.countV6Calls != 0 {
		t.Errorf("v6 total walk started %d times after v4 total cancellation, want 0", dp.countV6Calls)
	}
	assertCancelledAndReleased12180(t, err)
}

func TestGetSessionsFilteredTotalCancelsDuringV6Count12180(t *testing.T) {
	withSingleSessionWalkSlot12180(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dp := &cursorCancelDP12180{
		Manager: dataplane.New(), nV4: 1, nV6: 1,
		countV4Rows: 1, countV6Rows: cursorCancelTestRows12180,
		cancel: cancel, cancelAtCountV6: sessionWalkCancelInterval9060 / 2,
	}
	s := newViewServer(t, dp)

	_, err := s.GetSessions(ctx, &pb.GetSessionsRequest{Protocol: "udp", PageSize: 1})

	if dp.countV6Calls != 1 {
		t.Errorf("filtered total called v6 iterator %d times, want 1", dp.countV6Calls)
	}
	if dp.countV6Visited > sessionWalkCancelInterval9060 {
		t.Errorf("filtered total visited %d v6 rows after cancellation, want at most %d", dp.countV6Visited, sessionWalkCancelInterval9060)
	}
	assertCancelledAndReleased12180(t, err)
}

func TestGetSessionsUnfilteredTotalCancelsDuringV4Count12180(t *testing.T) {
	withSingleSessionWalkSlot12180(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dp := &cursorCancelDP12180{
		Manager: dataplane.New(), nV4: 1,
		countV4Rows: cursorCancelTestRows12180, countV6Rows: cursorCancelTestRows12180,
		cancel: cancel, cancelAtCountV4: sessionWalkCancelInterval9060 / 2,
	}
	s := newViewServer(t, dp)

	_, err := s.GetSessions(ctx, &pb.GetSessionsRequest{PageSize: 1})

	if dp.countV4Visited > sessionWalkCancelInterval9060 {
		t.Errorf("unfiltered total visited %d v4 rows after cancellation, want at most %d", dp.countV4Visited, sessionWalkCancelInterval9060)
	}
	if dp.countV4Calls != 1 {
		t.Errorf("unfiltered total called v4 iterator %d times, want 1", dp.countV4Calls)
	}
	if dp.countV6Calls != 0 {
		t.Errorf("unfiltered v6 total walk started %d times after v4 cancellation, want 0", dp.countV6Calls)
	}
	if dp.sessionCountCalls != 0 {
		t.Errorf("uncancellable SessionCount called %d times, want cancellable count iterator", dp.sessionCountCalls)
	}
	assertCancelledAndReleased12180(t, err)
}

func TestGetSessionsPageFullFilteredTotalCancelsDuringV4Count12180(t *testing.T) {
	withSingleSessionWalkSlot12180(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dp := &cursorCancelDP12180{
		Manager: dataplane.New(), nV4: 1,
		countV4Rows: cursorCancelTestRows12180, countV6Rows: 1,
		cancel: cancel, cancelAtCountV4: sessionWalkCancelInterval9060 / 2,
	}
	s := newViewServer(t, dp)

	_, err := s.GetSessions(ctx, &pb.GetSessionsRequest{Protocol: "tcp", PageSize: 1})

	if dp.cursorV4Visited == 0 {
		t.Fatal("fixture broken: v4 page did not fill before the total walk")
	}
	if dp.countV4Calls != 1 {
		t.Errorf("page-full filtered total called v4 iterator %d times, want 1", dp.countV4Calls)
	}
	if dp.countV4Visited > sessionWalkCancelInterval9060 {
		t.Errorf("page-full filtered total visited %d v4 rows after cancellation, want at most %d", dp.countV4Visited, sessionWalkCancelInterval9060)
	}
	if dp.countV6Calls != 0 {
		t.Errorf("v6 total walk started %d times after v4 total cancellation, want 0", dp.countV6Calls)
	}
	assertCancelledAndReleased12180(t, err)
}

func TestGetSessionsPageFullFilteredTotalCancelsDuringV6Count12180(t *testing.T) {
	withSingleSessionWalkSlot12180(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dp := &cursorCancelDP12180{
		Manager: dataplane.New(), nV6: 1,
		countV4Rows: 1, countV6Rows: cursorCancelTestRows12180,
		cancel: cancel, cancelAtCountV6: sessionWalkCancelInterval9060 / 2,
	}
	s := newViewServer(t, dp)

	_, err := s.GetSessions(ctx, &pb.GetSessionsRequest{
		Protocol: "tcp", PageSize: 1, PageToken: encodePageTokenV6Start(),
	})

	if dp.cursorV6Visited == 0 {
		t.Fatal("fixture broken: v6 page did not fill before the total walk")
	}
	if dp.countV4Calls != 1 || dp.countV6Calls != 1 {
		t.Errorf("page-full filtered total calls = v4:%d v6:%d, want 1/1", dp.countV4Calls, dp.countV6Calls)
	}
	if dp.countV6Visited > sessionWalkCancelInterval9060 {
		t.Errorf("page-full filtered total visited %d v6 rows after cancellation, want at most %d", dp.countV6Visited, sessionWalkCancelInterval9060)
	}
	assertCancelledAndReleased12180(t, err)
}
