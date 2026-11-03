package componenttypes

import "testing"

func TestLevelsRankTrustAuditInternal(t *testing.T) {
	for i, l := range []Level{LevelTrust, LevelAudit, LevelInternal} {
		if rank, known := l.Rank(); !known || rank != i {
			t.Errorf("%s.Rank() = %d, %v, want %d", l, rank, known, i)
		}
		if LevelAt(i) != l {
			t.Errorf("LevelAt(%d) = %q, want %s", i, LevelAt(i), l)
		}
	}
	if rank, known := Level("secret").Rank(); known || rank != 0 {
		t.Errorf("an unknown level ranks %d, %v, want 0 and unknown", rank, known)
	}
	if !LevelAudit.AtLeast(LevelTrust) || LevelTrust.AtLeast(LevelAudit) || !Level("secret").AtLeast(LevelTrust) {
		t.Error("AtLeast should order trust < audit < internal and rank an unknown level with trust")
	}
	if LevelAt(3) != "" || LevelAt(-1) != "" {
		t.Error("LevelAt outside the levels should be empty")
	}
}
