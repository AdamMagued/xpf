package cluster

import (
	"bytes"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
)

func TestHeartbeatStartedLogIncludesVRF12168(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	manager := keyedEpochManager(t, filepath.Join(t.TempDir(), "ha-boot-epoch"))
	t.Cleanup(manager.StopHeartbeat)
	if err := manager.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "em0"); err != nil {
		t.Fatalf("StartHeartbeat: %v", err)
	}
	manager.StopHeartbeat()
	if !strings.Contains(logs.String(), "cluster: heartbeat started") ||
		!strings.Contains(logs.String(), `vrf=""`) {
		t.Fatalf("heartbeat-started log does not include its VRF device: %s", logs.String())
	}
}
