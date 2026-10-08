package browser

import (
	"context"
	"errors"
	"testing"
)

func TestValidate(t *testing.T) {
	for _, link := range []string{"https://app.example.com/oauth2/device?user_code=WDJB-XKFT", "http://localhost:3000/x", " HTTPS://APP.EXAMPLE.COM "} {
		if err := Validate(link); err != nil {
			t.Errorf("Validate(%q) = %v, want nil", link, err)
		}
	}
	for _, link := range []string{"file:///Applications/Calculator.app", "/Applications/Calculator.app", "javascript:alert(1)", "ssh://host", "https://", "", "not a url"} {
		if err := Validate(link); !errors.Is(err, ErrUnsupportedURL) {
			t.Errorf("Validate(%q) = %v, want ErrUnsupportedURL", link, err)
		}
	}
}

func TestOpen_RefusesNonWebLinksWithoutLaunchingAnything(t *testing.T) {
	if err := Open(context.Background(), "file:///etc/passwd"); !errors.Is(err, ErrUnsupportedURL) {
		t.Fatalf("Open = %v, want ErrUnsupportedURL", err)
	}
}
