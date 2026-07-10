package config

import (
	"strings"
	"testing"
	"time"
)

func TestDecodeDefaultsAndStrictFields(t *testing.T) {
	yml := `
source:
  type: keycloak
  baseURL: https://keycloak.example
  realm: engineering
  clientID: groupbridge
  pollInterval: 15s
targets:
  - name: gitlab
    type: gitlab
    baseURL: https://gitlab.example
    tokenEnv: GITLAB_TOKEN
rules:
  - name: teams
    sourceGroupPrefix: /gitlab
    targetProvider: gitlab
    createGroups: false
    accessLevel: developer
    prune: managed-only
    maxRemovals: 10
    identityMatch: [username, email]
`
	c, err := Decode(strings.NewReader(yml))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if c.Server.Address != ":8080" || c.Source.PollInterval.Duration != 15*time.Second {
		t.Fatalf("unexpected defaults: %+v", c)
	}

	_, err = Decode(strings.NewReader(yml + "unknown: true\n"))
	if err == nil || !strings.Contains(err.Error(), "field unknown not found") {
		t.Fatalf("expected strict-field error, got %v", err)
	}
}

func TestDecodeRejectsDangerousOrInvalidRule(t *testing.T) {
	yml := `
source: {type: keycloak, baseURL: https://kc, realm: r, clientID: c, pollInterval: 1s}
targets: [{name: gl, type: gitlab, baseURL: https://gl, tokenEnv: TOKEN}]
rules: [{name: r, sourceGroupPrefix: relative, targetProvider: gl, accessLevel: owner, prune: everything, maxRemovals: -1, identityMatch: [username]}]
`
	_, err := Decode(strings.NewReader(yml))
	if err == nil {
		t.Fatal("expected validation error")
	}
	for _, want := range []string{"absolute sourceGroupPrefix", "accessLevel is invalid", "prune must be", "cannot be negative"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

func TestDecodeRequiresExplicitHTTPAndOIDCResolver(t *testing.T) {
	yml := `
source: {type: keycloak, baseURL: http://kc, realm: r, clientID: c, pollInterval: 1s}
targets: [{name: gl, type: gitlab, baseURL: http://gl, tokenEnv: TOKEN, oidcProvider: openid_connect}]
rules: [{name: r, sourceGroupPrefix: /, targetProvider: gl, accessLevel: developer, prune: managed-only, identityMatch: [oidc]}]
`
	_, err := Decode(strings.NewReader(yml))
	if err == nil {
		t.Fatal("expected secure transport and resolver validation errors")
	}
	for _, want := range []string{"allowInsecureHTTP", "resolverTokenEnv"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}
