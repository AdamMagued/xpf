package config

import (
	"fmt"
	"testing"
	"time"
)

func TestJunosHostApplicationCollisionWalkIsLinear12216(t *testing.T) {
	for _, n := range []int{11, 22} {
		apps := ApplicationsConfig{
			Applications:    map[string]*Application{"leaf": {Name: "leaf", Protocol: "tcp", DestinationPort: "80"}},
			ApplicationSets: make(map[string]*ApplicationSet, n),
			CollidingNames:  map[string]struct{}{"unrelated": {}},
		}
		for i := range n {
			members := []string{"leaf"}
			for j := i + 1; j < n; j++ {
				members = append(members, fmt.Sprintf("s%d", j))
			}
			name := fmt.Sprintf("s%d", i)
			apps.ApplicationSets[name] = &ApplicationSet{Name: name, Applications: members}
		}

		setBodies := 0
		start := time.Now()
		walkApplicationReference("s0", &apps,
			func(string, string, string) applicationReferenceCollisionAction {
				return applicationReferenceContinue
			}, nil, func(string) { setBodies++ }, nil)
		elapsed := time.Since(start)
		t.Logf("n=%d application sets: visited=%d cost=%v", n, setBodies, elapsed)
		if setBodies != n {
			t.Fatalf("visited %d set bodies for %d sets; the walk must visit each body once", setBodies, n)
		}
		if n == 22 && elapsed >= time.Second {
			t.Fatalf("n=22 collision walk took %v, want well under 1s", elapsed)
		}
	}
}
