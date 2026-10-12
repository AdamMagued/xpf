package configstore

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// A value committed by an older binary must not brick boot after the metric
// leaf becomes strict. Store.Load tolerates it but preserves a diagnostic.
func TestLoadToleratesPersistedInvalidQualifiedNextHopMetric12184(t *testing.T) {
	const persisted = `routing-options {
	static {
		route 0.0.0.0/0 {
			qualified-next-hop 192.168.1.1 {
				metric -1;
			}
		}
	}
}`
	path := filepath.Join(t.TempDir(), "config")
	tree, errs := config.NewParser(persisted).Parse()
	if len(errs) > 0 {
		t.Fatalf("precondition: persisted config must parse: %v", errs[0])
	}
	if err := newTestStoreAt(t, path).db.WriteActiveMarker(tree, true); err != nil {
		t.Fatalf("precondition: persist active config: %v", err)
	}

	booted := newTestStoreAt(t, path)
	if err := booted.Load(); err != nil {
		t.Fatalf("Store.Load refused a persisted invalid metric and could prevent boot: %v", err)
	}
	active := booted.ActiveConfig()
	if active == nil {
		t.Fatal("Store.Load succeeded but ActiveConfig is nil")
	}
	warnings := strings.Join(active.Warnings, "\n")
	for _, want := range []string{
		config.ToleratedTypedLeafWarningPrefix,
		"qualified-next-hop",
		"metric",
		"-1",
	} {
		if !strings.Contains(warnings, want) {
			t.Errorf("tolerated-load warnings %q do not name %q", warnings, want)
		}
	}
}
