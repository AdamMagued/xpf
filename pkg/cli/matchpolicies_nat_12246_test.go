package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/policymatch"
)

// TestShowMatchPoliciesRequiresPostDNATInput pins #12246 at the advertised
// packet-check surface. The dataplane evaluates policy after DNAT, so the
// simulator's policy-only tuple must be supplied post-DNAT. A VIP query may
// otherwise hit permit-vip even though a real VIP packet is translated to the
// denied server. The output must state the tuple-stage requirement alongside
// the verdict, and usage must name the expected input stage. Following the
// note — re-querying with the post-DNAT server tuple — must reach the
// dataplane's deny-server answer.
func TestShowMatchPoliciesRequiresPostDNATInput(t *testing.T) {
	cfg := &config.Config{Security: config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Zones: map[string]*config.ZoneConfig{
			"untrust": {Name: "untrust"},
			"trust":   {Name: "trust"},
		},
		NAT: config.NATConfig{Destination: &config.DestinationNATConfig{
			Pools: map[string]*config.NATPool{
				"srv-pool": {Name: "srv-pool", Address: "10.0.0.5", Port: 8080},
			},
			RuleSets: []*config.NATRuleSet{{
				Name:     "rs-dnat",
				FromZone: "untrust",
				Rules: []*config.NATRule{{
					Name: "vip-http",
					Match: config.NATMatch{
						DestinationAddress: "203.0.113.10",
						DestinationPort:    80,
						Protocol:           "tcp",
					},
					Then: config.NATThen{Type: config.NATDestination, PoolName: "srv-pool"},
				}},
			}},
		}},
		Policies: []*config.ZonePairPolicies{{
			FromZone: "untrust",
			ToZone:   "trust",
			Policies: []*config.Policy{
				{
					Name:   "permit-vip",
					Action: config.PolicyPermit,
					Match: config.PolicyMatch{
						SourceAddresses:      []string{"any"},
						DestinationAddresses: []string{"203.0.113.10/32"},
						Applications:         []string{"any"},
					},
				},
				{
					Name:   "deny-server",
					Action: config.PolicyDeny,
					Match: config.PolicyMatch{
						SourceAddresses:      []string{"any"},
						DestinationAddresses: []string{"10.0.0.5/32"},
						Applications:         []string{"any"},
					},
				},
			},
		}},
	}}

	out := captureStdout(t, func() {
		if err := (&CLI{}).showMatchPolicies(cfg, []string{
			"from-zone", "untrust", "to-zone", "trust",
			"source-ip", "198.51.100.7", "destination-ip", "203.0.113.10",
			"protocol", "tcp", "destination-port", "80",
		}); err != nil {
			t.Fatalf("showMatchPolicies: %v", err)
		}
	})
	if !strings.Contains(out, "post-DNAT") || !strings.Contains(out, "post-translation") {
		t.Fatalf("match-policies must state that destination-ip/port are expected post-DNAT; output:\n%s", out)
	}
	if !strings.Contains(out, "permit-vip") {
		t.Fatalf("the VIP-vs-real regression fixture did not exercise the literal VIP verdict; output:\n%s", out)
	}

	followed := captureStdout(t, func() {
		if err := (&CLI{}).showMatchPolicies(cfg, []string{
			"from-zone", "untrust", "to-zone", "trust",
			"source-ip", "198.51.100.7", "destination-ip", "10.0.0.5",
			"protocol", "tcp", "destination-port", "8080",
		}); err != nil {
			t.Fatalf("showMatchPolicies (post-DNAT tuple): %v", err)
		}
	})
	if !strings.Contains(followed, "deny-server") || strings.Contains(followed, "permit-vip") {
		t.Fatalf("the post-DNAT server tuple must reach the dataplane's deny-server verdict; output:\n%s", followed)
	}
	if !strings.Contains(followed, "NOTE: "+policymatch.PostNATInputRequirementNote) {
		t.Fatalf("every verdict under configured DNAT must carry the input requirement; output:\n%s", followed)
	}
}

// TestTestPolicyRequiresPostDNATInput12246 pins #12246 on the local
// operational `test policy` simulator (cli_request_testcmd.go): a VIP query
// against a committed DNAT config must print the post-DNAT input requirement
// alongside the literal VIP verdict, and the post-DNAT server tuple must reach
// the dataplane's deny-server answer.
//
// RED-on-revert: removing the NOTE print from testPolicy drops the line and
// both assertions on it fail.
func TestTestPolicyRequiresPostDNATInput12246(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
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
        from-zone untrust to-zone trust {
            policy permit-vip {
                match { source-address any; destination-address vip; application any; }
                then { permit; }
            }
            policy deny-server {
                match { source-address any; destination-address server; application any; }
                then { deny; }
            }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	c := &CLI{store: store}
	note := "NOTE: " + policymatch.PostNATInputRequirementNote

	for _, tc := range []struct {
		name, dst, port, policy string
	}{
		{name: "pre-NAT VIP", dst: "203.0.113.10", port: "80", policy: "permit-vip"},
		{name: "post-DNAT server", dst: "10.0.0.5", port: "8080", policy: "deny-server"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			out := captureStdout(t, func() {
				err = c.testPolicy([]string{
					"from-zone", "untrust", "to-zone", "trust",
					"source-ip", "198.51.100.7", "destination-ip", tc.dst,
					"protocol", "tcp", "destination-port", tc.port,
				})
			})
			if err != nil {
				t.Fatalf("testPolicy() err = %v", err)
			}
			if !strings.Contains(out, "Policy:    "+tc.policy) {
				t.Fatalf("PREMISE: %s query did not reach %s; output:\n%s", tc.name, tc.policy, out)
			}
			if !strings.Contains(out, note) {
				t.Fatalf("test policy must print the post-DNAT input requirement; output:\n%s", out)
			}
		})
	}
}
