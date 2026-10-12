// #5250 (A8-b2 F3): the session/NAT totals published over gRPC are int32
// protobuf fields fed from 64-bit accumulators. A bare `int32(v)` conversion
// WRAPS NEGATIVE past MaxInt32 — an operator reading `show security flow
// session summary` on a very large table would see a negative session count
// rather than a saturated one. A clampInt32 helper (server_nat.go, #2282)
// already existed in this package and simply was not applied at these sites.
//
// FAIL-ON-REVERT: TestClampInt32Saturates_5250 pins the positive, zero, and
// MaxInt32 overflow boundaries; TestNATSessionCountsAre64Bit_5250 pins the
// int64 accumulators that prevent wrapping before the clamp can run.
//
// Scope note (honest): the count path (setSessionsTotal's iterator scan,
// which now serves both filtered and unfiltered cases) and
// countNATSessions' per-rule-set map are only reachable past
// MaxInt32 by iterating >2^31 sessions, which no unit test can drive. Those
// two sites share the clamp helper asserted here and the 64-bit accumulator
// asserted below; neither is independently drivable in a unit test.
package grpcapi

import (
	"math"
	"reflect"
	"testing"
)

func TestNATSessionCountsAre64Bit_5250(t *testing.T) {
	ty := reflect.TypeOf(natSessionCounts{})
	f, ok := ty.FieldByName("total")
	if !ok {
		t.Fatal("natSessionCounts has no field total")
	}
	if f.Type.Kind() != reflect.Int64 {
		t.Fatalf("natSessionCounts.total is %s, want int64 — a 32-bit accumulator wraps NEGATIVE while counting, before any clamp can run", f.Type)
	}
	m, ok := ty.FieldByName("ruleSetSessions")
	if !ok {
		t.Fatal("natSessionCounts has no field ruleSetSessions")
	}
	if m.Type.Elem().Kind() != reflect.Int64 {
		t.Fatalf("natSessionCounts.ruleSetSessions value type is %s, want int64", m.Type.Elem())
	}
}

// The clamp itself: the boundary the two undrivable sites rely on.
func TestClampInt32Saturates_5250(t *testing.T) {
	for _, tc := range []struct {
		in   int64
		want int32
	}{
		{math.MaxInt32, math.MaxInt32},
		{math.MaxInt32 + 1, math.MaxInt32},
		{int64(math.MaxInt32) * 4, math.MaxInt32},
		{0, 0},
		{7, 7},
	} {
		if got := clampInt32(tc.in); got != tc.want {
			t.Errorf("clampInt32(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
