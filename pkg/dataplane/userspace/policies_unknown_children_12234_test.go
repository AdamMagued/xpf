package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

const applyGroupsExceptPolicy12217 = `groups {
    LOG {
        security {
            policies {
                from-zone <*> to-zone <*> {
                    policy <*> {
                        then {
                            log {
                                session-init;
                            }
                        }
                    }
                }
            }
        }
    }
}
apply-groups LOG;
security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone untrust {
            policy p {
                apply-groups-except LOG;
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then { permit; }
            }
            policy q {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then { permit; }
            }
        }
    }
}`

func TestApplyGroupsExceptPolicyRemainsAdvisory12217(t *testing.T) {
	tree, parseErrs := config.NewParser(applyGroupsExceptPolicy12217).Parse()
	if len(parseErrs) != 0 {
		t.Fatalf("parse apply-groups-except fixture: %v", parseErrs)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	var p, q *config.Policy
	for _, zpp := range cfg.Security.Policies {
		for _, pol := range zpp.Policies {
			switch pol.Name {
			case "p":
				p = pol
			case "q":
				q = pol
			}
		}
	}
	if p == nil || q == nil {
		t.Fatalf("compiled policies p and q are required: p=%v q=%v", p, q)
	}
	if p.LenientContentDropped {
		t.Fatal("apply-groups-except must not poison policy p")
	}
	if p.Log != nil {
		t.Fatalf("p.Log = %+v, want nil because the LOG group is excluded", p.Log)
	}
	if q.Log == nil || !q.Log.SessionInit {
		t.Fatalf("q.Log = %+v, want inherited session-init logging", q.Log)
	}

	rules, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, nil)
	if err != nil {
		t.Fatalf("build policy snapshots: %v", err)
	}
	var snapshotP, snapshotQ *PolicyRuleSnapshot
	for i := range rules {
		switch rules[i].Name {
		case "p":
			snapshotP = &rules[i]
		case "q":
			snapshotQ = &rules[i]
		}
	}
	if snapshotP == nil || snapshotQ == nil {
		t.Fatalf("snapshots p and q are required: p=%v q=%v", snapshotP, snapshotQ)
	}
	for _, term := range snapshotP.ApplicationTerms {
		if term.Name == unsupportedApplicationSentinel || term.Protocol == unsupportedApplicationSentinel {
			t.Fatalf("apply-groups-except emitted unsupported sentinel in p: %+v", snapshotP.ApplicationTerms)
		}
	}
	if snapshotP.LogSessionInit {
		t.Fatal("p snapshot inherited the excluded session-init log")
	}
	if !snapshotQ.LogSessionInit {
		t.Fatal("q snapshot lost the inherited session-init log")
	}
	if reasons := PolicyContentRejectionReasons(cfg, nil); len(reasons) != 0 {
		t.Fatalf("valid apply-groups-except unexpectedly rejects the policy snapshot: %v", reasons)
	}
	if !strings.Contains(strings.Join(cfg.Warnings, "\n"), "#4232") {
		t.Fatalf("apply-groups-except must retain the advisory: %v", cfg.Warnings)
	}
}

func TestPackedDescriptionTyposPoisonUserspaceSnapshot12234(t *testing.T) {
	cases := []struct {
		name         string
		child        string
		schedulerRef bool
	}{
		{name: "packed scheduler reference", child: `descripton "web" scheduler-name permit-window;`, schedulerRef: true},
		{name: "packed deny action", child: "descripton x then deny;"},
		{name: "nested description typo", child: "descriptio { x; }"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text := `schedulers {
    scheduler permit-window {
        daily { start-time 08:30; stop-time 09:00; }
    }
}
security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone untrust {
            policy p {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then { permit; }
                ` + tc.child + `
            }
        }
    }
}`
			tree, parseErrs := config.NewParser(text).Parse()
			if len(parseErrs) != 0 {
				t.Fatalf("parse packed description fixture: %v", parseErrs)
			}
			cfg, err := config.CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			var policy *config.Policy
			for _, zpp := range cfg.Security.Policies {
				for _, candidate := range zpp.Policies {
					if candidate.Name == "p" {
						policy = candidate
					}
				}
			}
			if policy == nil {
				t.Fatal("compiled policy p is missing")
			}
			if policy.Action != config.PolicyPermit {
				t.Fatalf("policy action = %v, want the control permit", policy.Action)
			}
			if !policy.LenientContentDropped {
				t.Fatalf("%s did not poison the tolerant policy", tc.name)
			}
			if tc.schedulerRef && policy.SchedulerName != "" {
				t.Fatalf("packed scheduler typo unexpectedly compiled scheduler %q", policy.SchedulerName)
			}
			rules, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, nil)
			if err != nil {
				t.Fatalf("build policy snapshots: %v", err)
			}
			var snapshot *PolicyRuleSnapshot
			for i := range rules {
				if rules[i].Name == "p" {
					snapshot = &rules[i]
					break
				}
			}
			if snapshot == nil {
				t.Fatal("snapshot for policy p is missing")
			}
			if len(snapshot.ApplicationTerms) != 1 ||
				snapshot.ApplicationTerms[0].Name != unsupportedApplicationSentinel ||
				snapshot.ApplicationTerms[0].Protocol != unsupportedApplicationSentinel {
				t.Fatalf("poisoned policy did not lower to the unsupported sentinel: %+v", snapshot.ApplicationTerms)
			}
			if reasons := PolicyContentRejectionReasons(cfg, nil); len(reasons) == 0 {
				t.Fatal("poisoned policy snapshot has no content-rejection reason")
			}
		})
	}
}
