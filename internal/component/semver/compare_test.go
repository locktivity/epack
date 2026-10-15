package semver

import "testing"

func TestCompare_FollowsSemverPrecedence(t *testing.T) {
	ordered := []string{
		"v0.4.9",
		"v0.5.0-alpha",
		"v0.5.0-alpha.1",
		"v0.5.0-alpha.beta",
		"v0.5.0-beta",
		"v0.5.0-beta.2",
		"v0.5.0-beta.11",
		"v0.5.0-rc.1",
		"v0.5.0-rc.9",
		"v0.5.0-rc.10",
		"v0.5.0",
		"v0.5.1",
		"v0.10.0",
		"v1.0.0",
	}
	for i := range ordered {
		for j := range ordered {
			a, err := ParseVersion(ordered[i])
			if err != nil {
				t.Fatal(err)
			}
			b, err := ParseVersion(ordered[j])
			if err != nil {
				t.Fatal(err)
			}
			want := 0
			switch {
			case i < j:
				want = -1
			case i > j:
				want = 1
			}
			if got := Compare(a, b); sign(got) != want {
				t.Errorf("Compare(%s, %s) = %d, want %d", ordered[i], ordered[j], got, want)
			}
		}
	}
}

func TestCompare_TreatsTheVPrefixAndLeadingZerosAsTheSameRelease(t *testing.T) {
	for _, pair := range [][2]string{{"0.5.0", "v0.5.0"}, {"v0.5.0-rc.09", "v0.5.0-rc.9"}} {
		a, _ := ParseVersion(pair[0])
		b, _ := ParseVersion(pair[1])
		if got := Compare(a, b); got != 0 {
			t.Errorf("Compare(%s, %s) = %d, want 0", pair[0], pair[1], got)
		}
	}
}

func TestSelectVersion_PicksTheNewestMatchingRelease(t *testing.T) {
	constraint, err := ParseConstraint("^0.5.0")
	if err != nil {
		t.Fatal(err)
	}
	got, err := SelectVersion([]string{"v0.5.2", "v0.5.10", "v0.5.9", "v0.6.0", "v0.5.11-rc.1"}, constraint)
	if err != nil {
		t.Fatal(err)
	}
	if got != "v0.5.10" {
		t.Errorf("SelectVersion = %s, want v0.5.10", got)
	}
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}
