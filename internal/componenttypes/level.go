package componenttypes

import "slices"

// Level is how much evidence a run collects. Each level holds all that the
// levels below it hold: trust, then audit, then internal.
type Level string

const (
	LevelTrust    Level = "trust"
	LevelAudit    Level = "audit"
	LevelInternal Level = "internal"
)

// levels lists the levels from lowest to highest.
var levels = []Level{LevelTrust, LevelAudit, LevelInternal}

// Rank returns l's place in the order trust, audit, internal, from 0. known
// is false for a value that names no level, which ranks with trust.
func (l Level) Rank() (rank int, known bool) {
	i := slices.Index(levels, l)
	if i < 0 {
		return 0, false
	}
	return i, true
}

// AtLeast reports whether l is at or above other. A value that names no
// level ranks with trust.
func (l Level) AtLeast(other Level) bool {
	a, _ := l.Rank()
	b, _ := other.Rank()
	return a >= b
}

// LevelAt returns the level at rank, the inverse of Rank. A rank outside
// the levels returns "".
func LevelAt(rank int) Level {
	if rank < 0 || rank >= len(levels) {
		return ""
	}
	return levels[rank]
}
