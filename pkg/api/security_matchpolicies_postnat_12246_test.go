package api

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/policymatch"
)

// postNAT12246Text renders the #12246 VIP-vs-real fixture: destination NAT
// 203.0.113.10:80 -> 10.0.0.5:8080 from untrust, default-policy deny, and the
// supplied untrust->trust policy stanzas.
func postNAT12246Text(policies string) string {
	return `
security {
    address-book {
        global {
            address vip 203.0.113.10/32;
            address server 10.0.0.5/32;
        }
    }
    zones {
        security-zone trust;
        security-zone untrust;
    }
    nat {
        destination {
            pool srv-pool {
                address 10.0.0.5/32 port 8080;
            }
            rule-set rs-dnat {
                from zone untrust;
                rule vip-http {
                    match {
                        destination-address 203.0.113.10/32;
                        destination-port 80;
                    }
                    then {
                        destination-nat pool srv-pool;
                    }
                }
            }
        }
    }
    policies {
        default-policy deny-all;
        from-zone untrust to-zone trust {` + policies + `
        }
    }
}
`
}

// postNAT12246VIPPolicies permits the pre-NAT VIP and denies the real server,
// so a VIP query and the dataplane's post-DNAT decision disagree.
const postNAT12246VIPPolicies = `
            policy permit-vip {
                match { source-address any; destination-address vip; application any; }
                then { permit; }
            }
            policy deny-server {
                match { source-address any; destination-address server; application any; }
                then { deny; }
            }`

// postNAT12246RejectedPolicies names an undefined application. Only the
// tolerant peer-sync ingress admits it; the userspace builder refuses the
// whole snapshot, so every query takes the content-rejected path.
const postNAT12246RejectedPolicies = `
            policy bad-app {
                match { source-address any; destination-address server; application no-such-app; }
                then { deny; }
            }`

// postNAT12246APIServer commits the VIP-vs-real fixture through the operator
// commit path.
func postNAT12246APIServer(t *testing.T) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(postNAT12246Text(postNAT12246VIPPolicies)); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return &Server{store: store}
}

// postNAT12246RejectedAPIServer installs the DNAT fixture with an
// unrepresentable policy through the tolerant peer-sync ingress.
func postNAT12246RejectedAPIServer(t *testing.T) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if _, err := store.SyncApply(postNAT12246Text(postNAT12246RejectedPolicies), nil); err != nil {
		t.Fatalf("SyncApply() error = %v", err)
	}
	return &Server{store: store}
}

// TestMatchPoliciesRESTCarriesPostNATInputNote12246 pins #12246 on every REST
// /security/match return path. The simulator does not perform inbound
// destination NAT, so whenever DNAT is configured each JSON verdict must carry
// post_nat_input_note; a client must never read a pre-NAT VIP verdict as the
// dataplane's post-DNAT decision.
//
// RED-on-revert: dropping PostNATInputNote from any matchPoliciesHandler
// return in pkg/api/security.go (content-rejected, host-inbound, unmatched,
// matched) omits the field on that path and the matching subtest fails.
func TestMatchPoliciesRESTCarriesPostNATInputNote12246(t *testing.T) {
	committed := postNAT12246APIServer(t)
	rejected := postNAT12246RejectedAPIServer(t)
	cases := []struct {
		name    string
		s       *Server
		q       url.Values
		premise func(MatchPoliciesResult) bool
	}{
		{
			name: "matched",
			s:    committed,
			q: url.Values{
				"from_zone": {"untrust"}, "to_zone": {"trust"}, "protocol": {"tcp"},
				"dst_ip": {"203.0.113.10"}, "dst_port": {"80"},
			},
			premise: func(r MatchPoliciesResult) bool {
				return r.Matched && r.PolicyName == "permit-vip"
			},
		},
		{
			name: "unmatched default",
			s:    committed,
			q: url.Values{
				"from_zone": {"trust"}, "to_zone": {"untrust"}, "protocol": {"tcp"},
				"dst_ip": {"203.0.113.10"}, "dst_port": {"80"},
			},
			premise: func(r MatchPoliciesResult) bool {
				return !r.Matched && r.DefaultUsed
			},
		},
		{
			name: "host-inbound unmatched",
			s:    committed,
			q: url.Values{
				"from_zone": {"untrust"}, "to_zone": {"junos-host"}, "protocol": {"tcp"},
				"dst_port": {"22"},
			},
			premise: func(r MatchPoliciesResult) bool {
				return r.HostInboundUnmatched
			},
		},
		{
			name: "content rejected",
			s:    rejected,
			q: url.Values{
				"from_zone": {"untrust"}, "to_zone": {"trust"}, "protocol": {"tcp"},
				"dst_ip": {"10.0.0.5"}, "dst_port": {"8080"},
			},
			premise: func(r MatchPoliciesResult) bool {
				return r.ContentRejected && !r.Matched
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/api/v1/security/match?"+tc.q.Encode(), nil)
			tc.s.matchPoliciesHandler(rr, req)
			if rr.Code != 200 {
				t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
			}
			var envelope struct {
				Success bool                `json:"success"`
				Data    MatchPoliciesResult `json:"data"`
			}
			if err := json.Unmarshal(rr.Body.Bytes(), &envelope); err != nil {
				t.Fatalf("decode response: %v; body: %s", err, rr.Body.String())
			}
			if !envelope.Success || !tc.premise(envelope.Data) {
				t.Fatalf("PREMISE: fixture did not reach the %s path; body: %s", tc.name, rr.Body.String())
			}
			if got := envelope.Data.PostNATInputNote; got != policymatch.PostNATInputRequirementNote {
				t.Errorf("post_nat_input_note = %q, want %q; body: %s", got, policymatch.PostNATInputRequirementNote, rr.Body.String())
			}
		})
	}
}
