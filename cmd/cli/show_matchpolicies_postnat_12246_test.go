package main

import (
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/policymatch"
)

// TestShowMatchPoliciesPrintsPostNATInputNote12246 pins #12246 on the REMOTE
// `show security match-policies`: when the daemon returns post_nat_input_note
// (inbound destination NAT is configured), the remote CLI must print it
// alongside every verdict shape so an operator does not read a pre-NAT VIP
// verdict as the dataplane's post-DNAT decision.
//
// RED-on-revert: removing the NOTE print from cmd/cli showMatchPolicies drops
// the line and every subtest fails.
func TestShowMatchPoliciesPrintsPostNATInputNote12246(t *testing.T) {
	note := policymatch.PostNATInputRequirementNote
	vipArgs := []string{
		"from-zone", "untrust", "to-zone", "trust",
		"protocol", "tcp", "destination-ip", "203.0.113.10", "destination-port", "80",
	}
	cases := []struct {
		name    string
		args    []string
		resp    *pb.MatchPoliciesResponse
		verdict string
	}{
		{
			name: "matched",
			args: vipArgs,
			resp: &pb.MatchPoliciesResponse{
				Matched: true, PolicyName: "permit-vip", Action: "permit",
				PostNatInputNote: note,
			},
			verdict: "Policy: permit-vip",
		},
		{
			name: "unmatched default",
			args: vipArgs,
			resp: &pb.MatchPoliciesResponse{
				Action: "deny (default)", DefaultUsed: true,
				PostNatInputNote: note,
			},
			verdict: "No matching policy found for untrust -> trust (deny (default))",
		},
		{
			name: "host-inbound unmatched",
			args: []string{
				"from-zone", "untrust", "to-zone", "junos-host",
				"protocol", "tcp", "destination-port", "22",
			},
			resp: &pb.MatchPoliciesResponse{
				HostInboundUnmatched: true, Action: policymatch.HostInboundActionString,
				PostNatInputNote: note,
			},
			verdict: policymatch.HostInboundShowLine,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeBpfrxClient{matchPoliciesResp: tc.resp}
			c := &ctl{client: fake}
			out := captureStdout(t, func() {
				if err := c.showMatchPolicies(tc.args); err != nil {
					t.Fatalf("showMatchPolicies: %v", err)
				}
			})
			if fake.matchPoliciesCalls != 1 {
				t.Fatalf("MatchPolicies called %d times, want 1", fake.matchPoliciesCalls)
			}
			if !strings.Contains(out, tc.verdict) {
				t.Fatalf("PREMISE: output missing the %s verdict %q:\n%s", tc.name, tc.verdict, out)
			}
			if !strings.Contains(out, "NOTE: "+note) {
				t.Fatalf("remote match-policies output must print the post-DNAT input requirement:\n%s", out)
			}
		})
	}
}
