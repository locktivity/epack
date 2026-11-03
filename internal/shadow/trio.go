package shadow

// trio holds one value for each of a shadow's three runs: the locked
// version's first and second runs and the candidate's.
type trio[T any] struct {
	Locked1, Locked2, Candidate T
}

// mapTrio applies f to each of t's values.
func mapTrio[T, U any](t trio[T], f func(T) U) trio[U] {
	return trio[U]{Locked1: f(t.Locked1), Locked2: f(t.Locked2), Candidate: f(t.Candidate)}
}

// inRunOrder returns t's values in the order a shadow runs them: the locked
// version, the candidate, then the locked version again.
func (t *trio[T]) inRunOrder() [3]*T {
	return [3]*T{&t.Locked1, &t.Candidate, &t.Locked2}
}

// anyFailed reports whether any of the three runs failed.
func anyFailed(runs trio[RunOutput]) bool {
	return runs.Locked1.Failed || runs.Locked2.Failed || runs.Candidate.Failed
}

// verdict is how one key compares across a shadow's three runs.
type verdict int

const (
	// kept is a key every run holds, with the candidate's value the same as
	// the locked runs'.
	kept verdict = iota
	// added is a key the candidate's run holds and neither locked run does.
	added
	// removed is a key both locked runs hold and the candidate's does not.
	removed
	// changed is a key every run holds, with the candidate's value
	// different from the locked runs'.
	changed
	// noisy is a key the two locked runs disagree on: one holds it and the
	// other does not, or they hold different values.
	noisy
)

// threeWay applies a shadow's rule to each key any of the three runs holds.
// A key the two locked runs disagree on is noise, and any other key is
// compared between the locked runs and the candidate's. same compares two
// values of a key both runs hold. A nil same compares presence alone.
func threeWay[K comparable, V any](runs trio[map[K]V], same func(a, b V) bool) map[K]verdict {
	out := map[K]verdict{}
	for _, m := range []map[K]V{runs.Locked1, runs.Locked2, runs.Candidate} {
		for k := range m {
			if _, done := out[k]; !done {
				out[k] = judge(runs, k, same)
			}
		}
	}
	return out
}

// judge applies threeWay's rule to one key.
func judge[K comparable, V any](runs trio[map[K]V], k K, same func(a, b V) bool) verdict {
	v1, in1 := runs.Locked1[k]
	v2, in2 := runs.Locked2[k]
	vb, inB := runs.Candidate[k]
	differ := func(a, b V) bool { return same != nil && !same(a, b) }
	switch {
	case in1 != in2 || (in1 && differ(v1, v2)):
		return noisy
	case !in1:
		return added
	case !inB:
		return removed
	case differ(v1, vb):
		return changed
	}
	return kept
}
