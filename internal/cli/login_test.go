package cli

import "testing"

// isWebURL is the guard that keeps the authorization server's
// verification URI from reaching the OS browser openers, so its
// rejections are the security property: every attack shape from the
// finding must stay rejected, and the legitimate shapes (plain http
// loopback — which device flows in development use — and case variants)
// must stay accepted. Control bytes are rejected implicitly by
// url.Parse's control-character check; if this ever moves to a
// hand-rolled parser, that check must come with it.
func TestIsWebURL(t *testing.T) {
	cases := map[string]bool{
		// accepted: plain web URLs
		"https://auth.example.com/device?code=ABCD": true,
		"http://localhost:8080/device":              true,
		"HTTPS://AUTH.EXAMPLE.COM/D":                true, // url.Parse lowercases the scheme
		"https://auth.example.com/path ok?q=1":      true,

		// rejected: non-web schemes would launch the OS handler
		"file:///System/Applications/Calculator.app": false,
		"file://attacker/share/payload":              false,
		"ssh://git@host/repo":                        false,
		"javascript:alert(1)":                        false,
		"custom://x":                                 false,

		// rejected: URLs that could mislead or smuggle
		"https://evil@auth.example.com/device":       false, // userinfo — phishing-shaped
		"https://":                                   false, // no host
		"//no-scheme.example.com/device":             false,
		"https://auth.example.com/de\x1b[2Jvice":     false, // ANSI escape
		"https://auth.example.com/a\r\nSet-Cookie:x": false, // header-style smuggling
	}
	for in, want := range cases {
		if got := isWebURL(in); got != want {
			t.Errorf("isWebURL(%q) = %v, want %v", in, got, want)
		}
	}
}
