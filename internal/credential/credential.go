// Package credential loads provider credentials without caching file contents.
package credential

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxCredentialBytes = 1 << 20

// Loader resolves one credential source. File-backed loaders reopen the path
// for every Load call so Kubernetes projected-Secret symlink swaps are seen.
type Loader struct {
	environment string
	filePath    string
	staticValue *string
}

// New creates an environment- or file-backed Loader. Exactly one source is
// required so configuration can never silently fall back to a stale value.
func New(environment, filePath string) (Loader, error) {
	if environment != "" && filePath != "" {
		return Loader{}, errors.New("credential environment variable and file are mutually exclusive")
	}
	if environment == "" && filePath == "" {
		return Loader{}, errors.New("credential requires exactly one environment variable or file")
	}
	if filePath != "" {
		if !filepath.IsAbs(filePath) {
			return Loader{}, errors.New("credential file must be an absolute path")
		}
		if filepath.Clean(filePath) != filePath {
			return Loader{}, errors.New("credential file path must be canonical")
		}
	}
	return Loader{environment: environment, filePath: filePath}, nil
}

// Static creates a Loader for compatibility constructors and tests. Runtime
// configuration should prefer New so Kubernetes credentials can rotate.
func Static(value string) Loader {
	return Loader{staticValue: &value}
}

// Load resolves and validates the current credential value. Errors identify
// only the source and never include credential contents.
func (l Loader) Load() (string, error) {
	var value string
	switch {
	case l.staticValue != nil:
		value = *l.staticValue
	case l.environment != "":
		raw, ok := os.LookupEnv(l.environment)
		if !ok {
			return "", fmt.Errorf("required credential environment variable %s is unset", l.environment)
		}
		value = raw
	case l.filePath != "":
		f, err := os.Open(l.filePath)
		if err != nil {
			return "", fmt.Errorf("read credential file %s: %w", l.filePath, err)
		}
		data, readErr := io.ReadAll(io.LimitReader(f, maxCredentialBytes+1))
		closeErr := f.Close()
		if readErr != nil {
			return "", fmt.Errorf("read credential file %s: %w", l.filePath, readErr)
		}
		if closeErr != nil {
			return "", fmt.Errorf("close credential file %s: %w", l.filePath, closeErr)
		}
		if len(data) > maxCredentialBytes {
			return "", fmt.Errorf("credential file %s exceeds %d bytes", l.filePath, maxCredentialBytes)
		}
		value = string(data)
	default:
		return "", errors.New("credential loader is not configured")
	}

	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("credential is empty")
	}
	if !utf8.ValidString(value) || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return "", errors.New("credential contains invalid control characters")
	}
	return value, nil
}
