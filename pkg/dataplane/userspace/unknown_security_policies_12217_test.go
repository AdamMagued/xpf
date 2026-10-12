package userspace

import (
	"strings"
	"testing"
)

func TestUnknownPoliciesChildRefusesSnapshot12217(t *testing.T) {
	snap := lenientSnapshot5575(t, [][]string{
		{"security", "zones", "security-zone", "trust"},
		{"security", "zones", "security-zone", "untrust"},
		{"security", "policies", "default-policy", "permit-all"},
		{"security", "policies", "global", "policy", "g-permit", "match", "source-address", "any"},
		{"security", "policies", "global", "policy", "g-permit", "match", "destination-address", "any"},
		{"security", "policies", "global", "policy", "g-permit", "match", "application", "any"},
		{"security", "policies", "global", "policy", "g-permit", "then", "permit"},
		{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "p", "match", "source-address", "any"},
		{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "p", "match", "destination-address", "any"},
		{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "p", "match", "application", "any"},
		{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "p", "then", "permit"},
		{"security", "policies", "globel", "policy", "deny-bad", "match", "source-address", "any"},
		{"security", "policies", "globel", "policy", "deny-bad", "match", "destination-address", "any"},
		{"security", "policies", "globel", "policy", "deny-bad", "match", "application", "any"},
		{"security", "policies", "globel", "policy", "deny-bad", "then", "deny"},
	})
	if !snapshotHasAppSentinel5575(snap) {
		t.Fatal("snapshot lacks the __unsupported__ sentinel for the dropped deny child; the incomplete rulebase would not be refused")
	}
	if len(snap.Capabilities.PolicyContentRejected) != 1 {
		t.Fatalf("snapshot PolicyContentRejected = %v, want exactly one reason for the dropped deny child", snap.Capabilities.PolicyContentRejected)
	}
	rejection := strings.Join(snap.Capabilities.PolicyContentRejected, "\n")
	if strings.Contains(rejection, "lenient-dropped-policy-enforcement-constraint") {
		t.Fatalf("snapshot rejection reason exposes the generic poison carrier: %s", rejection)
	}
	if !strings.Contains(rejection, `unknown security policies child "globel" was skipped`) {
		t.Fatalf("snapshot rejection reason does not name the skipped globel child: %v", snap.Capabilities.PolicyContentRejected)
	}
}
