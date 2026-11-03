package componentsdk

// Rounding is the rounding mode for a whole-number percentage. Its values
// match a schema's x-epack-rounding.
type Rounding string

const (
	// RoundDown is for a percentage where more is better, such as MFA
	// coverage. A shortfall is then never rounded up to 100.
	RoundDown Rounding = "floor"
	// RoundUp is for a percentage where more is worse, such as rules open to
	// the world. An exposure is then never rounded down to 0.
	RoundUp Rounding = "ceil"
	// RoundNearest rounds to the nearest whole number, with halves rounded
	// up.
	RoundNearest Rounding = "nearest"
)

// Percent returns count as a whole percentage of total, rounded with
// rounding. It returns nil when total is 0, because a percentage over no
// population has no value. It also returns nil when count is not between 0
// and total, or when rounding is not one of the three modes. The output
// checks then report the null instead of a wrong number. The normalized
// schemas give each percentage's rounding in x-epack-rounding.
func Percent(count, total int, rounding Rounding) *int {
	if total <= 0 || count < 0 || count > total {
		return nil
	}
	var p int
	switch rounding {
	case RoundDown:
		p = count * 100 / total
	case RoundUp:
		p = (count*100 + total - 1) / total
	case RoundNearest:
		p = (count*200 + total) / (2 * total)
	default:
		return nil
	}
	return &p
}
