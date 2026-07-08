package builder

import (
	"testing"
)

// Reject over-budget artifacts before retaining them.
func TestAddBytes_RejectsCumulativeSizeIncrementally(t *testing.T) {
	b := New("test/stream")
	b.maxPackSize = 100

	if err := b.AddBytes("artifacts/a.bin", make([]byte, 60)); err != nil {
		t.Fatalf("first artifact should fit: %v", err)
	}
	if err := b.AddBytes("artifacts/b.bin", make([]byte, 60)); err == nil {
		t.Fatal("expected the second artifact to exceed the pack size budget")
	}
	if len(b.artifacts) != 1 {
		t.Errorf("rejected artifact must not be retained: have %d", len(b.artifacts))
	}
	if b.totalSize != 60 {
		t.Errorf("totalSize must reflect only accepted artifacts: %d", b.totalSize)
	}
}

func TestAddBytes_RejectsCountIncrementally(t *testing.T) {
	b := New("test/stream")
	b.maxArtifactCount = 2

	for _, name := range []string{"artifacts/a.bin", "artifacts/b.bin"} {
		if err := b.AddBytes(name, []byte("x")); err != nil {
			t.Fatalf("artifact %s should fit: %v", name, err)
		}
	}
	if err := b.AddBytes("artifacts/overflow.bin", []byte("x")); err == nil {
		t.Fatal("expected the third artifact to exceed the artifact count budget")
	}
	if len(b.artifacts) != 2 {
		t.Errorf("rejected artifact must not be retained: have %d", len(b.artifacts))
	}
}
