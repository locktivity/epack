package componentsdk

import (
	"strconv"
	"testing"
)

func TestPercent(t *testing.T) {
	cases := []struct {
		count, total int
		rounding     Rounding
		want         *int
	}{
		{1, 201, RoundDown, new(0)},
		{1, 201, RoundUp, new(1)},
		{1, 201, RoundNearest, new(0)},
		{996, 1000, RoundDown, new(99)},
		{996, 1000, RoundUp, new(100)},
		{996, 1000, RoundNearest, new(100)},
		{1, 2, RoundNearest, new(50)},
		{1, 3, RoundNearest, new(33)},
		{2, 3, RoundNearest, new(67)},
		{1, 200, RoundNearest, new(1)},
		{0, 5, RoundUp, new(0)},
		{5, 5, RoundDown, new(100)},
		{0, 0, RoundDown, nil},
		{-1, 5, RoundDown, nil},
		{6, 5, RoundUp, nil},
		{1, 2, Rounding("banker"), nil},
	}
	for _, tc := range cases {
		got := Percent(tc.count, tc.total, tc.rounding)
		switch {
		case got == nil && tc.want == nil:
		case got == nil || tc.want == nil || *got != *tc.want:
			t.Errorf("Percent(%d, %d, %s) = %s, want %s", tc.count, tc.total, tc.rounding, showInt(got), showInt(tc.want))
		}
	}
}

func showInt(p *int) string {
	if p == nil {
		return "nil"
	}
	return strconv.Itoa(*p)
}
