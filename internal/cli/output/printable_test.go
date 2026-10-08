package output

import "testing"

func TestPrintable(t *testing.T) {
	cases := map[string]string{
		"WDJB-XKFT":                     "WDJB-XKFT",
		"https://app.example.com/x?y=1": "https://app.example.com/x?y=1",
		"Signed in\x1b[2K\rfake line":   "Signed in[2Kfake line",
		"tab\tand\nnewline":             "tabandnewline",
		"bidi\u202eoverride":            "bidioverride",
		"caf\u00e9 \u2713":              "caf\u00e9 \u2713",
		"bad\xffbyte":                   "badbyte",
	}
	for in, want := range cases {
		if got := Printable(in); got != want {
			t.Errorf("Printable(%q) = %q, want %q", in, got, want)
		}
	}
}
