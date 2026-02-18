package output

// Palette provides color formatting that respects NO_COLOR.
type Palette struct {
	enabled bool
}

// NewPalette creates a new color palette.
// If enabled is false, all methods return the input unchanged.
func NewPalette(enabled bool) *Palette {
	return &Palette{enabled: enabled}
}

// ANSI escape codes
const (
	reset     = "\033[0m"
	bold      = "\033[1m"
	dim       = "\033[2m"
	red       = "\033[31m"
	green     = "\033[32m"
	yellow    = "\033[33m"
	blue      = "\033[34m"
	magenta   = "\033[35m"
	cyan      = "\033[36m"
	boldRed   = "\033[1;31m"
	boldGreen = "\033[1;32m"
)

func (p *Palette) wrap(code, s string) string {
	if !p.enabled || s == "" {
		return s
	}
	return code + s + reset
}

// Bold returns bold text.
func (p *Palette) Bold(s string) string {
	return p.wrap(bold, s)
}

// Dim returns dimmed text.
func (p *Palette) Dim(s string) string {
	return p.wrap(dim, s)
}

// Red returns red text.
func (p *Palette) Red(s string) string {
	return p.wrap(red, s)
}

// Green returns green text.
func (p *Palette) Green(s string) string {
	return p.wrap(green, s)
}

// Yellow returns yellow text.
func (p *Palette) Yellow(s string) string {
	return p.wrap(yellow, s)
}

// Blue returns blue text.
func (p *Palette) Blue(s string) string {
	return p.wrap(blue, s)
}

// Magenta returns magenta text.
func (p *Palette) Magenta(s string) string {
	return p.wrap(magenta, s)
}

// Cyan returns cyan text.
func (p *Palette) Cyan(s string) string {
	return p.wrap(cyan, s)
}

// BoldRed returns bold red text (for errors).
func (p *Palette) BoldRed(s string) string {
	return p.wrap(boldRed, s)
}

// BoldGreen returns bold green text (for success).
func (p *Palette) BoldGreen(s string) string {
	return p.wrap(boldGreen, s)
}

// Success formats a success indicator.
func (p *Palette) Success(s string) string {
	if p.enabled {
		return p.Green("✓") + " " + s
	}
	return "[OK] " + s
}

// Failure formats a failure indicator.
func (p *Palette) Failure(s string) string {
	if p.enabled {
		return p.Red("✗") + " " + s
	}
	return "[FAIL] " + s
}
