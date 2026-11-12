package roster

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// The attributes a roster can leave unsettled.
const (
	unsettledMFA      = "mfa"
	unsettledSignedIn = "signed_in"
)

// settledSignIn is the sign-in age an unsettled account takes when it is
// taken as active.
const settledSignIn = 1

// Realization is a roster with every unsettled attribute decided one way.
type Realization struct {
	// Name lists the choices, such as "creator.mfa=none", or is empty for a
	// roster with nothing unsettled.
	Name   string
	Roster *Roster
}

// Realizations returns r once for each way its unsettled attributes could
// turn out. An unsettled mfa is either the account's methods or none, or one
// method mapped to mfa when it has none. An unsettled signed_in is either the
// account's sign-in or never, or a sign-in a day ago when it has none.
func (r *Roster) Realizations() ([]Realization, error) {
	type choice struct {
		account int
		attr    string
	}
	var choices []choice
	for i, a := range r.Accounts {
		for _, attr := range r.Unsettled[a.Key] {
			choices = append(choices, choice{i, attr})
		}
	}
	var mfaMethod string
	for _, vendor := range sortedKeys(r.Terms.MFAMethods) {
		if r.Terms.MFAMethods[vendor] == MFA {
			mfaMethod = vendor
			break
		}
	}

	var out []Realization
	for bits := 0; bits < 1<<len(choices); bits++ {
		c := r.Clone()
		c.Unsettled = nil
		var names []string
		for i, ch := range choices {
			if bits&(1<<i) == 0 {
				continue
			}
			a := &c.Accounts[ch.account]
			switch ch.attr {
			case unsettledMFA:
				if r.MFAClass(*a) != MFANone {
					a.Methods = nil
				} else if mfaMethod == "" {
					return nil, fmt.Errorf("%s.mfa is unsettled and terms.mfa_methods maps no method to mfa", a.Key)
				} else {
					a.Methods = []string{mfaMethod}
				}
				names = append(names, a.Key+".mfa="+r.MFAClass(*a))
			case unsettledSignedIn:
				if a.SignedInDaysAgo != nil {
					a.SignedInDaysAgo = nil
					names = append(names, a.Key+".signed_in=never")
				} else {
					days := settledSignIn
					a.SignedInDaysAgo = &days
					names = append(names, a.Key+".signed_in=recent")
				}
			}
		}
		out = append(out, Realization{Name: strings.Join(names, ","), Roster: c})
	}
	return out, nil
}

// Expect is what a roster with unsettled attributes says one pointer must
// hold: an exact value, a range of integers, or either boolean.
type Expect struct {
	Exact  any
	Min    int
	Max    int
	Range  bool
	Either bool
}

func (e Expect) String() string {
	switch {
	case e.Either:
		return "either"
	case e.Range:
		return fmt.Sprintf("{min: %d, max: %d}", e.Min, e.Max)
	case e.Exact == nil:
		return "null"
	default:
		return fmt.Sprint(e.Exact)
	}
}

// Settle derives the values once for every realization and merges them: a
// value every realization agrees on is exact, and one that differs becomes a
// range, or either for a boolean or a percentage that is null in one.
func Settle(r *Roster) (map[string]map[string]Expect, error) {
	realizations, err := r.Realizations()
	if err != nil {
		return nil, err
	}
	merged := map[string]map[string]Expect{}
	for _, real := range realizations {
		values, err := Derive(real.Roster)
		if err != nil {
			return nil, err
		}
		for kind, pointers := range values {
			if merged[kind] == nil {
				merged[kind] = map[string]Expect{}
			}
			for pointer, value := range pointers {
				prev, seen := merged[kind][pointer]
				merged[kind][pointer] = mergeExpect(prev, seen, value)
			}
		}
	}
	return merged, nil
}

func mergeExpect(prev Expect, seen bool, value any) Expect {
	n, isInt := value.(int)
	if !seen {
		if isInt {
			return Expect{Exact: n, Min: n, Max: n}
		}
		return Expect{Exact: value}
	}
	_, prevInt := prev.Exact.(int)
	switch {
	case prev.Either:
		return prev
	case isInt && (prev.Range || prevInt):
		prev.Min, prev.Max = min(prev.Min, n), max(prev.Max, n)
		prev.Range = prev.Min != prev.Max
		if prev.Range {
			prev.Exact = nil
		}
		return prev
	case !prev.Range && sameValue(prev.Exact, value):
		return prev
	default:
		return Expect{Either: true}
	}
}

// Holds reports whether got, a value decoded from JSON, meets e.
func (e Expect) Holds(got any) bool {
	if e.Either {
		return true
	}
	n, isNumber := asInt(got)
	if e.Range {
		return isNumber && n >= e.Min && n <= e.Max
	}
	if want, ok := e.Exact.(int); ok {
		return isNumber && n == want
	}
	return sameValue(e.Exact, got)
}

// sameValue reports whether two values encode to the same JSON, so a
// derived list or count by name compares with one decoded from an artifact.
func sameValue(a, b any) bool {
	ra, errA := json.Marshal(a)
	rb, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(ra, rb)
}

func asInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case float64:
		return int(n), n == float64(int(n))
	default:
		return 0, false
	}
}
