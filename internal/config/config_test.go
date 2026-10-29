package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSettingsRoundTrip(t *testing.T) {
	t.Setenv("ZQ_CONFIG_DIR", t.TempDir())
	if s, _ := LoadSettings(); s.APIBase != "" {
		t.Fatalf("fresh settings should be empty, got %+v", s)
	}
	want := Settings{APIBase: "https://zq.corp.example.com"}
	if err := SaveSettings(want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if got.APIBase != want.APIBase {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestTokensRoundTripAndPermissions(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ZQ_CONFIG_DIR", dir)

	if tokens, _ := LoadTokens(); tokens != nil {
		t.Fatalf("fresh dir should have no tokens, got %+v", tokens)
	}
	want := &Tokens{
		AccessToken: "AT", RefreshToken: "RT",
		Expiry: 12345, Issuer: "https://auth/realms/z", APIBase: "https://api",
	}
	if err := SaveTokens(want); err != nil {
		t.Fatal(err)
	}

	f, err := Resolve()
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(f.Credentials)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("credentials.json permissions = %o, want 600", perm)
	}

	got, err := LoadTokens()
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != want.AccessToken || got.RefreshToken != want.RefreshToken ||
		got.Issuer != want.Issuer || got.APIBase != want.APIBase || got.Expiry != want.Expiry {
		t.Fatalf("round trip mismatch: %+v vs %+v", got, want)
	}

	// Loose permissions from an older version are repaired on save.
	if err := os.Chmod(f.Credentials, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := SaveTokens(want); err != nil {
		t.Fatal(err)
	}
	info, _ = os.Stat(f.Credentials)
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("permissions not repaired: %o", perm)
	}

	if err := ClearTokens(); err != nil {
		t.Fatal(err)
	}
	if tokens, _ := LoadTokens(); tokens != nil {
		t.Fatal("ClearTokens left tokens behind")
	}
	// Idempotent.
	if err := ClearTokens(); err != nil {
		t.Fatal(err)
	}
}

func TestCorruptCredentialsFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ZQ_CONFIG_DIR", dir)
	f, _ := Resolve()
	if err := os.WriteFile(f.Credentials, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadTokens()
	if err == nil || !filepath.IsAbs(f.Credentials) {
		t.Fatalf("want corrupt-file error, got %v", err)
	}
}

func TestDirOverrides(t *testing.T) {
	custom := filepath.Join(t.TempDir(), "custom-zq")
	t.Setenv("ZQ_CONFIG_DIR", custom)
	f, err := Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if f.Dir != custom {
		t.Fatalf("ZQ_CONFIG_DIR ignored: %s", f.Dir)
	}
	if _, err := os.Stat(custom); err != nil {
		t.Fatalf("directory not created: %v", err)
	}
}
