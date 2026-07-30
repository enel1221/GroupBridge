package config

import (
	"fmt"
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
	if c.Server.Address != ":8080" || c.Source.PollInterval.Duration != 15*time.Second ||
		c.Source.ClientSecretEnv != "GROUPBRIDGE_KEYCLOAK_CLIENT_SECRET" {
		t.Fatalf("unexpected defaults: %+v", c)
	}

	_, err = Decode(strings.NewReader(yml + "unknown: true\n"))
	if err == nil || !strings.Contains(err.Error(), "field unknown not found") {
		t.Fatalf("expected strict-field error, got %v", err)
	}
}

func TestDecodeSupportsNativeServerTLS(t *testing.T) {
	yml := `
server:
  address: :8443
  tls:
    certFile: /var/run/tls/tls.crt
    keyFile: /var/run/tls/tls.key
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
    accessLevel: developer
    prune: none
    identityMatch: [username]
`
	cfg, err := Decode(strings.NewReader(yml))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if cfg.Server.TLS.CertFile != "/var/run/tls/tls.crt" ||
		cfg.Server.TLS.KeyFile != "/var/run/tls/tls.key" {
		t.Fatalf("server TLS = %+v", cfg.Server.TLS)
	}
}

func TestDecodeSupportsAbsoluteWebhookSecretFileAndRejectsAmbiguousSources(t *testing.T) {
	base := `
webhook:
  secretFile: /var/run/secrets/groupbridge-event/webhook-secret
source: {type: keycloak, baseURL: https://kc, realm: r, clientID: c, pollInterval: 1s}
targets: [{name: gl, type: gitlab, baseURL: https://gl, tokenEnv: TOKEN}]
rules: [{name: r, sourceGroupPrefix: /, targetProvider: gl, accessLevel: developer, prune: none, identityMatch: [username]}]
`
	cfg, err := Decode(strings.NewReader(base))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Webhook.SecretEnv != "" ||
		cfg.Webhook.SecretFile != "/var/run/secrets/groupbridge-event/webhook-secret" {
		t.Fatalf("webhook secret source = %+v", cfg.Webhook)
	}
	for name, webhook := range map[string]string{
		"both": `webhook:
  secretEnv: GROUPBRIDGE_WEBHOOK_SECRET
  secretFile: /var/run/secrets/groupbridge-event/webhook-secret`,
		"relative": `webhook:
  secretEnv: ""
  secretFile: relative/webhook-secret`,
	} {
		t.Run(name, func(t *testing.T) {
			start := strings.Index(base, "webhook:")
			end := strings.Index(base, "source:")
			input := base[:start] + webhook + "\n" + base[end:]
			if _, err := Decode(strings.NewReader(input)); err == nil {
				t.Fatal("expected webhook secret source validation error")
			}
		})
	}
}

func TestDecodeRejectsIncompleteOrRelativeServerTLS(t *testing.T) {
	base := `
server:
  tls:
%s
source: {type: keycloak, baseURL: https://kc, realm: r, clientID: c, pollInterval: 1s}
targets: [{name: gl, type: gitlab, baseURL: https://gl, tokenEnv: TOKEN}]
rules: [{name: r, sourceGroupPrefix: /, targetProvider: gl, accessLevel: developer, prune: none, identityMatch: [username]}]
`
	for name, fields := range map[string]string{
		"cert only":     "    certFile: /tls/tls.crt",
		"key only":      "    keyFile: /tls/tls.key",
		"relative cert": "    certFile: tls.crt\n    keyFile: /tls/tls.key",
		"relative key":  "    certFile: /tls/tls.crt\n    keyFile: tls.key",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Decode(strings.NewReader(fmt.Sprintf(base, fields)))
			if err == nil || !strings.Contains(err.Error(), "server.tls") {
				t.Fatalf("expected server.tls validation error, got %v", err)
			}
		})
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

func TestDecodeSupportsProviderBoundOIDCUsernameMatching(t *testing.T) {
	yml := `
source: {type: keycloak, baseURL: https://kc, realm: r, clientID: c, pollInterval: 1s}
targets:
  - name: gl
    type: gitlab
    baseURL: https://gl
    tokenEnv: TOKEN
    resolverTokenEnv: RESOLVER
    oidcProvider: openid_connect
rules:
  - name: r
    sourceGroupPrefix: /
    targetProvider: gl
    accessLevel: developer
    prune: managed-only
    identityMatch: [oidc-username]
`
	cfg, err := Decode(strings.NewReader(yml))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if got := cfg.Rules[0].IdentityMatch; len(got) != 1 || got[0] != "oidc-username" {
		t.Fatalf("identityMatch = %#v", got)
	}

	for name, target := range map[string]string{
		"missing provider": "resolverTokenEnv: RESOLVER",
		"missing resolver": "oidcProvider: openid_connect",
	} {
		t.Run(name, func(t *testing.T) {
			bad := strings.Replace(yml,
				"    resolverTokenEnv: RESOLVER\n    oidcProvider: openid_connect",
				"    "+target,
				1,
			)
			if _, err := Decode(strings.NewReader(bad)); err == nil ||
				!strings.Contains(err.Error(), "uses oidc-username matching") {
				t.Fatalf("expected oidc-username dependency error, got %v", err)
			}
		})
	}

	withFallback := strings.Replace(yml,
		"identityMatch: [oidc-username]",
		"identityMatch: [oidc-username, username]",
		1,
	)
	if _, err := Decode(strings.NewReader(withFallback)); err == nil ||
		!strings.Contains(err.Error(), "oidc-username must be the only identityMatch strategy") {
		t.Fatalf("expected unsafe fallback rejection, got %v", err)
	}
}

func TestDecodeSupportsExclusiveFileBackedProviderCredentials(t *testing.T) {
	yml := `
source:
  type: keycloak
  baseURL: https://kc
  realm: r
  clientID: c
  clientSecretFile: /var/run/secrets/groupbridge/keycloak-client-secret
  pollInterval: 1s
targets:
  - name: gl
    type: gitlab
    baseURL: https://gl
    tokenFile: /var/run/secrets/groupbridge/gitlab-token
    resolverTokenFile: /var/run/secrets/groupbridge/gitlab-resolver-token
    oidcProvider: openid_connect
rules:
  - name: r
    sourceGroupPrefix: /
    targetProvider: gl
    accessLevel: developer
    prune: managed-only
    identityMatch: [oidc]
`
	cfg, err := Decode(strings.NewReader(yml))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if cfg.Source.ClientSecretEnv != "" ||
		cfg.Source.ClientSecretFile != "/var/run/secrets/groupbridge/keycloak-client-secret" ||
		cfg.Targets[0].TokenEnv != "" ||
		cfg.Targets[0].TokenFile != "/var/run/secrets/groupbridge/gitlab-token" ||
		cfg.Targets[0].ResolverTokenFile != "/var/run/secrets/groupbridge/gitlab-resolver-token" {
		t.Fatalf("unexpected credential config: source=%+v target=%+v", cfg.Source, cfg.Targets[0])
	}
}

func TestDecodeRejectsAmbiguousOrUnsafeProviderCredentialSources(t *testing.T) {
	tests := map[string]struct {
		sourceFields string
		targetFields string
		want         string
	}{
		"source both": {
			sourceFields: "clientSecretEnv: KEYCLOAK_SECRET\n  clientSecretFile: /secret",
			targetFields: "tokenEnv: TOKEN",
			want:         "source.clientSecretEnv and source.clientSecretFile are mutually exclusive",
		},
		"gitlab mutation both": {
			sourceFields: "clientSecretEnv: KEYCLOAK_SECRET",
			targetFields: "tokenEnv: TOKEN\n    tokenFile: /token",
			want:         "targets[0].tokenEnv and targets[0].tokenFile are mutually exclusive",
		},
		"gitlab mutation neither": {
			sourceFields: "clientSecretEnv: KEYCLOAK_SECRET",
			targetFields: "resolverTokenEnv: RESOLVER",
			want:         "requires exactly one of targets[0].tokenEnv or targets[0].tokenFile",
		},
		"gitlab resolver both": {
			sourceFields: "clientSecretEnv: KEYCLOAK_SECRET",
			targetFields: "tokenEnv: TOKEN\n    resolverTokenEnv: RESOLVER\n    resolverTokenFile: /resolver",
			want:         "targets[0].resolverTokenEnv and targets[0].resolverTokenFile are mutually exclusive",
		},
		"relative source file": {
			sourceFields: "clientSecretFile: relative/secret",
			targetFields: "tokenEnv: TOKEN",
			want:         "clientSecretFile must be an absolute path",
		},
		"relative target file": {
			sourceFields: "clientSecretEnv: KEYCLOAK_SECRET",
			targetFields: "tokenFile: relative/token",
			want:         "tokenFile must be an absolute path",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			yml := `
source:
  type: keycloak
  baseURL: https://kc
  realm: r
  clientID: c
  ` + tt.sourceFields + `
  pollInterval: 1s
targets:
  - name: gl
    type: gitlab
    baseURL: https://gl
    ` + tt.targetFields + `
rules:
  - name: r
    sourceGroupPrefix: /
    targetProvider: gl
    accessLevel: developer
    prune: managed-only
    identityMatch: [username]
`
			_, err := Decode(strings.NewReader(yml))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
		})
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
		"static token file": {yaml: `
source: {type: keycloak, baseURL: https://kc, realm: r, clientID: c, pollInterval: 1s}
targets: [{name: vault, type: vault, baseURL: https://vault, tokenFile: /root-token, resolverTokenFile: /resolver, oidcMount: oidc, kvMount: orgs, kubernetesAuth: {mount: kubernetes, role: groupbridge, tokenFile: /token}}]
rules: [{name: r, sourceGroupPrefix: /Internal, targetProvider: vault, prune: managed-only, vault: {pathPrefix: internal, accessProfile: editor}}]
`, want: "must not use tokenEnv, tokenFile, resolverTokenEnv, or resolverTokenFile"},
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
