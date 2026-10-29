// Package config owns the CLI's two on-disk files:
//
//	config.json      — non-secret settings (the saved API base URL)
//	credentials.json — the device-flow OAuth tokens (chmod 0600)
//
// The CLI is a courier, not a vault: no *scan* credential ever touches
// disk here. The only secret this package stores is the CLI's own
// login token, which is the same class of artifact `gh` keeps in
// ~/.config/gh/hosts.yml — it authenticates the user, it never carries
// a target's credentials.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// DefaultAPIBase is the hosted ZeroQuarry deployment the CLI talks to
// when nothing else is configured. Self-hosted deployments override it
// per invocation (--api, ZQ_URL) or persist it with `zq login --api ...`.
const DefaultAPIBase = "https://api.zeroquarry.com"

// Files holds the resolved paths for the two on-disk files.
type Files struct {
	Dir         string // e.g. ~/.config/zq (respects XDG_CONFIG_HOME)
	Config      string // settings
	Credentials string // OAuth tokens, 0600
}

// Dir resolves the per-user config directory.
func dir() (string, error) {
	if override := os.Getenv("ZQ_CONFIG_DIR"); override != "" {
		return override, nil
	}
	if runtime.GOOS != "windows" {
		if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
			return filepath.Join(xdg, "zq"), nil
		}
	}
	// os.UserConfigDir(): ~/Library/Application Support on macOS,
	// %AppData% on Windows, ~/.config elsewhere (XDG default).
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "zq"), nil
}

// Resolve locates (creating the directory, 0700, if needed) the paths
// for both files.
func Resolve() (Files, error) {
	d, err := dir()
	if err != nil {
		return Files{}, err
	}
	if err := os.MkdirAll(d, 0o700); err != nil {
		return Files{}, err
	}
	return Files{
		Dir:         d,
		Config:      filepath.Join(d, "config.json"),
		Credentials: filepath.Join(d, "credentials.json"),
	}, nil
}

// Settings is the non-secret config file.
type Settings struct {
	APIBase string `json:"api_base,omitempty"`
}

// LoadSettings reads config.json; a missing file yields defaults.
func LoadSettings() (Settings, error) {
	var s Settings
	f, err := Resolve()
	if err != nil {
		return s, err
	}
	raw, err := os.ReadFile(f.Config)
	if errors.Is(err, os.ErrNotExist) {
		return Settings{}, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return s, fmt.Errorf("config file %s is corrupt: %w", f.Config, err)
	}
	return s, nil
}

// SaveSettings writes config.json (0644 — non-secret).
func SaveSettings(s Settings) error {
	f, err := Resolve()
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(f.Config, append(raw, '\n'), 0o644)
}

// Tokens is the credentials.json payload: the OAuth tokens from the
// device flow, plus enough context to refresh them.
type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	// Expiry is a unix second; the token is proactively refreshed when
	// now >= Expiry-60.
	Expiry  int64  `json:"expiry,omitempty"`
	Issuer  string `json:"issuer,omitempty"`
	APIBase string `json:"api_base,omitempty"`
}

// LoadTokens reads credentials.json; missing returns (nil, nil).
func LoadTokens() (*Tokens, error) {
	f, err := Resolve()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(f.Credentials)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var t Tokens
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, fmt.Errorf("credentials file %s is corrupt; run `zq login` again", f.Credentials)
	}
	if t.AccessToken == "" {
		return nil, nil
	}
	return &t, nil
}

// SaveTokens writes credentials.json with 0600 permissions and repairs
// an existing file that has looser permissions (e.g. written by an
// older version) before an attacker-with-backup-access could read it.
func SaveTokens(t *Tokens) error {
	f, err := Resolve()
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	if info, statErr := os.Stat(f.Credentials); statErr == nil {
		if perm := info.Mode().Perm(); perm != 0o600 {
			if chErr := os.Chmod(f.Credentials, 0o600); chErr != nil {
				return chErr
			}
		}
	}
	return os.WriteFile(f.Credentials, append(raw, '\n'), 0o600)
}

// ClearTokens removes credentials.json (idempotent).
func ClearTokens() error {
	f, err := Resolve()
	if err != nil {
		return err
	}
	err = os.Remove(f.Credentials)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
