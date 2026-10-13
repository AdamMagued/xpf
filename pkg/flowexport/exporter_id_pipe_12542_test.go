package flowexport

import "testing"

// FAIL-ON-REVERT (#12542): a `|` or `\` in an instance or template name
// must not forge a field boundary or the inet6 `|v6` family suffix. Every
// escaping rule has a pair below that hashes identically when the rule
// breaks: the issue's exact pair (both 3185142171) when the template is
// written raw, the backslash pair when `\` is left unescaped, and the
// instance-forged pair when the instance is written raw. With no escaping
// at all, the issue, field-boundary, and instance-forged pairs collide.

func TestStableExporterIDPipeFamilySuffixDistinct12542(t *testing.T) {
	for _, protocol := range []string{"netflow9", "ipfix"} {
		pipe := stableExporterID(protocol, "inst0", "t|v6", false)
		v6 := stableExporterID(protocol, "inst0", "t", true)
		if pipe == 0 || v6 == 0 {
			t.Fatalf("%s: zero id (pipe=%d v6=%d)", protocol, pipe, v6)
		}
		if pipe == v6 {
			t.Fatalf("%s: inet template t|v6 collides with inet6 template t (id=%d)", protocol, pipe)
		}
	}
}

func TestStableExporterIDPipeFieldBoundaryDistinct12542(t *testing.T) {
	a := stableExporterID("netflow9", "a|b", "c", false)
	b := stableExporterID("netflow9", "a", "b|c", false)
	if a == b {
		t.Fatalf("field-boundary collision: instance a|b/template c == instance a/template b|c (id=%d)", a)
	}
}

// TestStableExporterIDBackslashFamilySuffixDistinct12542: without the
// `\` → `\\` rule, inet6 template `t\` serializes as `...|t\|v6`, the same
// bytes as inet template `t|v6`.
func TestStableExporterIDBackslashFamilySuffixDistinct12542(t *testing.T) {
	for _, protocol := range []string{"netflow9", "ipfix"} {
		v6 := stableExporterID(protocol, "inst0", "t\\", true)
		pipe := stableExporterID(protocol, "inst0", "t|v6", false)
		if v6 == pipe {
			t.Fatalf("%s: inet6 template t\\ collides with inet template t|v6 (id=%d)", protocol, v6)
		}
	}
}

// TestStableExporterIDInstanceForgedFamilySuffixDistinct12542: with the
// instance written raw, inet instance `i|t` with template `v6` serializes
// as `...|i|t|v6`, the same bytes as inet6 instance `i` with template `t`.
func TestStableExporterIDInstanceForgedFamilySuffixDistinct12542(t *testing.T) {
	for _, protocol := range []string{"netflow9", "ipfix"} {
		forged := stableExporterID(protocol, "i|t", "v6", false)
		v6 := stableExporterID(protocol, "i", "t", true)
		if forged == v6 {
			t.Fatalf("%s: inet instance i|t template v6 collides with inet6 instance i template t (id=%d)", protocol, forged)
		}
	}
}

// TestStableExporterIDEscapeDeterministic12542: escaped names stay
// deterministic, nonzero, and pairwise distinct within one family, which
// catches an escape that maps `\` and `|` alike. It also passes with no
// escaping; the family-crossing pairs above are the revert pins.
func TestStableExporterIDEscapeDeterministic12542(t *testing.T) {
	cases := []string{"x\\", "x|", "x\\|y", "|", "\\", "t|v6"}
	seen := map[string]uint32{}
	for _, name := range cases {
		a := stableExporterID("netflow9", "i", name, false)
		b := stableExporterID("netflow9", "i", name, false)
		if a != b {
			t.Fatalf("nondeterministic id for %q: %d vs %d", name, a, b)
		}
		if a == 0 {
			t.Fatalf("zero id for %q", name)
		}
		seen[name] = a
	}
	for i := range cases {
		for j := i + 1; j < len(cases); j++ {
			if seen[cases[i]] == seen[cases[j]] {
				t.Fatalf("collision: %q == %q (id=%d)", cases[i], cases[j], seen[cases[i]])
			}
		}
	}
}

// TestStableExporterIDZeroAlloc12542 pins the single-Write key build: a key
// that fits the 128-byte stack buffer is hashed with no heap allocation.
// FAIL-ON-REVERT: the first #12542 cut wrote each escaped byte through the
// hash.Hash64 interface and allocated per byte (19 allocs for netflow9
// inst0/tmplA).
func TestStableExporterIDZeroAlloc12542(t *testing.T) {
	cases := []struct {
		instance, template string
		isV6               bool
	}{
		{"inst0", "tmplA", false},
		{"inst0", "t|v6", false},
		{"i|t", "t\\", true},
	}
	for _, protocol := range []string{"netflow9", "ipfix"} {
		for _, c := range cases {
			var id uint32
			allocs := testing.AllocsPerRun(100, func() {
				id = stableExporterID(protocol, c.instance, c.template, c.isV6)
			})
			if id == 0 {
				t.Fatalf("%s %q/%q v6=%v: zero id", protocol, c.instance, c.template, c.isV6)
			}
			if allocs != 0 {
				t.Fatalf("%s %q/%q v6=%v: stableExporterID allocated %v times per call, want 0",
					protocol, c.instance, c.template, c.isV6, allocs)
			}
		}
	}
}
