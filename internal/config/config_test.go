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
    prune: none
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

func TestDecodeVaultTargetAndRule(t *testing.T) {
	yml := `
source: {type: keycloak, baseURL: https://kc, realm: r, clientID: c, pollInterval: 1s}
targets:
  - name: vault
    type: vault
    baseURL: https://vault.example
    oidcMount: oidc
    kvMount: orgs
    kubernetesAuth:
      mount: kubernetes
      role: groupbridge
      tokenFile: /var/run/secrets/tokens/vault
rules:
  - name: vault-orgs
    sourceGroupPrefix: /Internal
    targetProvider: vault
    prune: none
    vault:
      pathPrefix: internal
      accessProfile: editor
      policyMode: verify-only
`
	c, err := Decode(strings.NewReader(yml))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if c.Targets[0].KubernetesAuth.TokenFile != "/var/run/secrets/tokens/vault" {
		t.Fatalf("unexpected target: %+v", c.Targets[0])
	}
	if c.Rules[0].Vault == nil || c.Rules[0].Vault.AccessProfile != "editor" {
		t.Fatalf("unexpected rule: %+v", c.Rules[0])
	}
}

func TestDecodeRejectsUnsafeVaultConfiguration(t *testing.T) {
	tests := map[string]struct {
		yaml string
		want string
	}{
		"static token": {yaml: `
source: {type: keycloak, baseURL: https://kc, realm: r, clientID: c, pollInterval: 1s}
targets: [{name: vault, type: vault, baseURL: https://vault, tokenEnv: ROOT_TOKEN, oidcMount: oidc, kvMount: orgs, kubernetesAuth: {mount: kubernetes, role: groupbridge, tokenFile: /token}}]
rules: [{name: r, sourceGroupPrefix: /Internal, targetProvider: vault, prune: managed-only, vault: {pathPrefix: internal, accessProfile: editor}}]
`, want: "must not use tokenEnv"},
		"bad mount": {yaml: `
source: {type: keycloak, baseURL: https://kc, realm: r, clientID: c, pollInterval: 1s}
targets: [{name: vault, type: vault, baseURL: https://vault, oidcMount: ../oidc, kvMount: orgs/data, kubernetesAuth: {mount: kubernetes, role: groupbridge, tokenFile: relative}}]
rules: [{name: r, sourceGroupPrefix: /Internal, targetProvider: vault, prune: authoritative, vault: {pathPrefix: ../root, accessProfile: admin}}]
`, want: "safe mount path"},
		"gitlab fields": {yaml: `
source: {type: keycloak, baseURL: https://kc, realm: r, clientID: c, pollInterval: 1s}
targets: [{name: vault, type: vault, baseURL: https://vault, oidcMount: oidc, kvMount: orgs, kubernetesAuth: {mount: kubernetes, role: groupbridge, tokenFile: /token}}]
rules: [{name: r, sourceGroupPrefix: /Internal, targetProvider: vault, accessLevel: developer, identityMatch: [username], prune: managed-only, vault: {pathPrefix: internal, accessProfile: editor}}]
`, want: "GitLab-only fields"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Decode(strings.NewReader(tt.yaml))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestDecodeValidatesExactSourceGroupPaths(t *testing.T) {
	base := `
source: {type: keycloak, baseURL: https://kc, realm: r, clientID: c, pollInterval: 1s}
targets:
  - {name: vault, type: vault, baseURL: https://vault, oidcMount: oidc, kvMount: orgs, kubernetesAuth: {mount: kubernetes, role: groupbridge, tokenFile: /token}}
rules:
  - name: r
    sourceGroupPrefix: /Internal
    sourceGroupPaths: [/Internal/CCMO, /Internal/CCMO/J6]
    targetProvider: vault
    prune: none
    vault: {pathPrefix: internal, accessProfile: editor, policyMode: verify-only}
`
	cfg, err := Decode(strings.NewReader(base))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Rules[0].SourceGroupPaths == nil || len(cfg.Rules[0].SourceGroupPaths) != 2 {
		t.Fatalf("exact paths were not retained: %+v", cfg.Rules[0])
	}
	for name, replacement := range map[string]string{
		"relative":  "sourceGroupPaths: [Internal/CCMO]",
		"outside":   "sourceGroupPaths: [/Other/CCMO]",
		"duplicate": "sourceGroupPaths: [/Internal/CCMO, /Internal/CCMO]",
		"collision": "sourceGroupPaths: [/Internal/Team, /Internal/team]",
		"unsafe":    "sourceGroupPaths: [/Internal/a%2fb]",
	} {
		t.Run(name, func(t *testing.T) {
			start := strings.Index(base, "sourceGroupPaths:")
			end := strings.Index(base[start:], "\n") + start
			input := base[:start] + replacement + base[end:]
			if _, err := Decode(strings.NewReader(input)); err == nil {
				t.Fatalf("expected %s allowlist to fail", name)
			}
		})
	}
}

func TestDecodeAllowsExactPathsBelowRootPrefix(t *testing.T) {
	yml := `
source: {type: keycloak, baseURL: https://kc, realm: r, clientID: c, pollInterval: 1s}
targets: [{name: gl, type: gitlab, baseURL: https://gl, tokenEnv: TOKEN}]
rules:
  - {name: r, sourceGroupPrefix: /, sourceGroupPaths: [/Internal], targetProvider: gl, accessLevel: developer, prune: managed-only, identityMatch: [username]}
`
	if _, err := Decode(strings.NewReader(yml)); err != nil {
		t.Fatalf("root-prefix exact path failed: %v", err)
	}
}
