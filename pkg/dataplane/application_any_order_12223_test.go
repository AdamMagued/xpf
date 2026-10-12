package dataplane

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #12223 control: the application-list lowerer treats `any` as a wildcard.
// With services application-identification disabled, the legacy
// compileApplications prepass rejects an accompanying undefined name. When
// enabled, it walks the full catalog, so userspace per-reference validation
// is the sole gate.
func TestCompileApplicationsRejectsUnknownBesideAny12223(t *testing.T) {
	tests := []struct {
		name    string
		appID   bool
		wantErr bool
	}{
		{"application-identification disabled", false, true},
		{"application-identification enabled", true, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Services.ApplicationIdentification = test.appID
			cfg.Security.Policies = []*config.ZonePairPolicies{{
				FromZone: "trust",
				ToZone:   "untrust",
				Policies: []*config.Policy{{
					Name: "p",
					Match: config.PolicyMatch{
						Applications: []string{"any", "no-such-app-12223"},
					},
					Action: config.PolicyPermit,
				}},
			}}

			err := compileApplications(discardingDataPlane{}, cfg, newValidationResult())
			if !test.wantErr {
				if err != nil {
					t.Fatalf("compileApplications error = %v, want nil with full-catalog prepass", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), `application "no-such-app-12223" not found`) {
				t.Fatalf("compileApplications error = %v, want missing-app prepass rejection", err)
			}
		})
	}
}
