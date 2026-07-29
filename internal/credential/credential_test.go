package credential

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileLoaderReopensRotatedCredential(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(" \nfirst-token\t"), 0o600); err != nil {
		t.Fatal(err)
	}
	loader, err := New("", path)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := loader.Load(); err != nil || got != "first-token" {
		t.Fatalf("first Load() = %q, %v", got, err)
	}
	if err := os.WriteFile(path, []byte("rotated-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := loader.Load(); err != nil || got != "rotated-token" {
		t.Fatalf("rotated Load() = %q, %v", got, err)
	}
}

func TestEnvironmentLoaderRetainsLegacyBehavior(t *testing.T) {
	t.Setenv("GROUPBRIDGE_TEST_CREDENTIAL", "environment-token")
	loader, err := New("GROUPBRIDGE_TEST_CREDENTIAL", "")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := loader.Load(); err != nil || got != "environment-token" {
		t.Fatalf("Load() = %q, %v", got, err)
	}
}

func TestLoaderRejectsAmbiguousUnsafeOrInvalidSourcesWithoutLeakingValues(t *testing.T) {
	t.Setenv("GROUPBRIDGE_TEST_SECRET", "do-not-leak-this")
	secretPath := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secretPath, []byte("also-do-not-leak"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, source := range map[string][2]string{
		"both":     {"GROUPBRIDGE_TEST_SECRET", secretPath},
		"neither":  {"", ""},
		"relative": {"", "relative/secret"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(source[0], source[1]); err == nil {
				t.Fatal("expected source validation error")
			}
		})
	}

	for name, value := range map[string]string{
		"blank":   " \t ",
		"control": "token\ninjected",
		"large":   strings.Repeat("x", maxCredentialBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "secret")
			if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
				t.Fatal(err)
			}
			loader, err := New("", path)
			if err != nil {
				t.Fatal(err)
			}
			_, err = loader.Load()
			if err == nil {
				t.Fatal("expected credential read error")
			}
			if strings.Contains(err.Error(), value) || strings.Contains(err.Error(), "do-not-leak") {
				t.Fatalf("credential value leaked in error: %v", err)
			}
		})
	}
}
