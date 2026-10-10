package flowexport

import "testing"

// FAIL-ON-REVERT (#12542): pipe-bearing names must not collide with the
// family suffix or field boundaries. Removing the writeEscapedField calls
// makes the issue's exact pair hash identically (both 3185142171).

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
	for i := 0; i < len(cases); i++ {
		for j := i + 1; j < len(cases); j++ {
			if seen[cases[i]] == seen[cases[j]] {
				t.Fatalf("collision: %q == %q (id=%d)", cases[i], cases[j], seen[cases[i]])
			}
		}
	}
}
