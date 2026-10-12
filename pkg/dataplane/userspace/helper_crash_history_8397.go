package userspace

import "time"

// #8397 keeps two distinct views: a bounded ring of completed recovery
// episodes for the operator, and a monotonic counter of every unexpected
// helper exit for Prometheus. A persistent crash loop may not complete an
// episode during its quiet window, so the metric must not be derived from the
// ring.

// WHY A SEPARATE STORE AND NOT MORE FIELDS ON THE RECORD. The live record's
// contract is "the current crash episode"; its fields are all cleared together
// when quiet recovery or an ordinary generation-advancing Compile ends that
// episode. Keeping some fields across that boundary would mix lifetimes and
// force every reader to know which fields survive. The separate history ring
// and exit counter preserve the completed facts without weakening that contract.
//
// The history and metric deliberately have different lifetimes:
//
//   - WHERE IT LIVES: both are on the Manager and reset on daemon restart.
//     The completed-episode ring is diagnostic detail; the cumulative exit
//     counter is the alert signal and increments immediately on every
//     unexpected helper exit.
//   - RENDERED OR QUERYABLE: BOTH, but minimally. `show chassis forwarding` is
//     already dense, so the history contributes ONE summary row: the number of
//     completed episodes and the age of the oldest retained one. Prometheus
//     observes the cumulative exit counter, including while a sustained loop
//     has not yet completed a quiet window.

// helperCrashHistoryDepth bounds retained episode details. A flapping helper
// must not grow this without limit; the separate episode total and unexpected-
// exit counter remain unbounded so a wrapped ring still reports honestly.
const helperCrashHistoryDepth = 8

// HelperCrashEpisode is one COMPLETED crash episode: an unexpected helper exit
// and everything that followed until the helper was running again.
//
// It is deliberately not a copy of HelperCrashRecord. That type carries live
// episode state (RestartPending, NextRestart, LastExitWasCrash) whose meaning
// depends on the episode still being open; an episode in this ring is closed by
// construction, so those fields would be dead weight that a reader has to know
// to ignore.
type HelperCrashEpisode struct {
	// At is when the unexpected exit was observed.
	At time.Time
	// ExitCode is the child's exit status, or -1 when it was signalled or the
	// status could not be read. Signal is the discriminator — exactly one of
	// the two is meaningful, matching HelperCrashRecord's split.
	ExitCode int
	// Signal is the signal name when the child was killed by one, otherwise "".
	Signal string
	// Detail is the reaped disposition ("exit status 101", "killed by signal
	// killed"). Never carries a secret.
	Detail string
	// PID is the dead child, kept so an operator can correlate with journald.
	PID int
	// Restarts is how many restart ATTEMPTS the episode took before the helper
	// reached readiness again.
	Restarts int
	// RecoveredAt is when the replacement helper reached readiness. The
	// episode may be journaled after its quiet window expires.
	RecoveredAt time.Time
}

// recordRecoveredCrashEpisodeLocked appends an episode before its live record
// is discarded. It runs after a quiet gap closes an episode with a landed
// retry, or when a generation-advancing Compile proves recovery. `now` is the
// Compile recovery time or quiet-gap detection time; a supervisor retry's
// recorded ready time takes precedence when available.
//
// Caller must hold m.mu.
func (m *Manager) recordRecoveredCrashEpisodeLocked(now time.Time) {
	recoveredAt := m.helperCrash.RecoveredAt
	if recoveredAt.IsZero() {
		recoveredAt = now
	}
	ep := HelperCrashEpisode{
		At:          m.helperCrash.At,
		ExitCode:    m.helperCrash.ExitCode,
		Signal:      m.helperCrash.Signal,
		Detail:      m.helperCrash.Detail,
		PID:         m.helperCrash.PID,
		Restarts:    m.helperCrash.Restarts,
		RecoveredAt: recoveredAt,
	}
	m.helperCrashEpisodes = append(m.helperCrashEpisodes, ep)
	if len(m.helperCrashEpisodes) > helperCrashHistoryDepth {
		// Drop the OLDEST. Copying into a fresh slice rather than reslicing so
		// the backing array cannot grow without bound across many wraps.
		trimmed := make([]HelperCrashEpisode, helperCrashHistoryDepth)
		copy(trimmed, m.helperCrashEpisodes[len(m.helperCrashEpisodes)-helperCrashHistoryDepth:])
		m.helperCrashEpisodes = trimmed
	}
	m.helperCrashEpisodesTotal++
}

// HelperCrashHistory returns the retained crash episodes oldest-first, and the
// TOTAL number of episodes this daemon has recovered from.
//
// The total is returned separately and is not bounded by the ring: a daemon
// that has recovered from 40 crashes reports 40 with the last
// helperCrashHistoryDepth episodes in hand. Returning only the slice would make
// a wrapped ring indistinguishable from a full one, which is the difference
// between "8 crashes" and "at least 8 crashes" — and this surface exists to
// answer "is this recurring?", where that distinction is the answer.
func (m *Manager) HelperCrashHistory() ([]HelperCrashEpisode, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]HelperCrashEpisode, len(m.helperCrashEpisodes))
	copy(out, m.helperCrashEpisodes)
	return out, m.helperCrashEpisodesTotal
}

// HelperCrashExitCount returns the daemon-lifetime count of unexpected helper
// exits. It is independent of the bounded episode ring and is never reset when
// an episode recovers.
func (m *Manager) HelperCrashExitCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.helperCrashUnexpectedExitsTotal
}
