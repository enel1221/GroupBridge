// Package config loads and strictly validates GroupBridge configuration.
package config

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server  Server   `yaml:"server"`
	Webhook Webhook  `yaml:"webhook"`
	Source  Source   `yaml:"source"`
	Targets []Target `yaml:"targets"`
	Rules   []Rule   `yaml:"rules"`
	State   State    `yaml:"state"`
}

type Server struct {
	Address         string   `yaml:"address"`
	ShutdownTimeout Duration `yaml:"shutdownTimeout"`
}

type Webhook struct {
	SecretEnv string   `yaml:"secretEnv"`
	MaxSkew   Duration `yaml:"maxSkew"`
}

type Source struct {
	Type              string   `yaml:"type"`
	BaseURL           string   `yaml:"baseURL"`
	AllowInsecureHTTP bool     `yaml:"allowInsecureHTTP"`
	Realm             string   `yaml:"realm"`
	ClientID          string   `yaml:"clientID"`
	ClientSecretEnv   string   `yaml:"clientSecretEnv"`
	PollInterval      Duration `yaml:"pollInterval"`
}

type Target struct {
	Name              string              `yaml:"name"`
	Type              string              `yaml:"type"`
	BaseURL           string              `yaml:"baseURL"`
	AllowInsecureHTTP bool                `yaml:"allowInsecureHTTP"`
	TokenEnv          string              `yaml:"tokenEnv"`
	ResolverTokenEnv  string              `yaml:"resolverTokenEnv"`
	OIDCProvider      string              `yaml:"oidcProvider"`
	OIDCMount         string              `yaml:"oidcMount"`
	KVMount           string              `yaml:"kvMount"`
	KubernetesAuth    VaultKubernetesAuth `yaml:"kubernetesAuth"`
}

type VaultKubernetesAuth struct {
	Mount     string `yaml:"mount"`
	Role      string `yaml:"role"`
	TokenFile string `yaml:"tokenFile"`
}

type Rule struct {
	Name               string     `yaml:"name"`
	SourceGroupPrefix  string     `yaml:"sourceGroupPrefix"`
	SourceGroupPaths   []string   `yaml:"sourceGroupPaths"`
	TargetProvider     string     `yaml:"targetProvider"`
	TargetParent       string     `yaml:"targetParent"`
	CreateGroups       bool       `yaml:"createGroups"`
	AdoptExistingGroup bool       `yaml:"adoptExistingGroup"`
	AccessLevel        string     `yaml:"accessLevel"`
	Prune              string     `yaml:"prune"`
	ProtectedUsers     []string   `yaml:"protectedUsers"`
	MaxRemovals        int        `yaml:"maxRemovals"`
	IdentityMatch      []string   `yaml:"identityMatch"`
	EnforceAccessLevel bool       `yaml:"enforceAccessLevel"`
	Vault              *VaultRule `yaml:"vault"`
}

type VaultRule struct {
	PathPrefix    string `yaml:"pathPrefix"`
	AccessProfile string `yaml:"accessProfile"`
	PolicyMode    string `yaml:"policyMode"`
	Discoverable  bool   `yaml:"discoverable"`
}

type State struct {
	Path string `yaml:"path"`
}

type Duration struct{ time.Duration }

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	v, err := time.ParseDuration(node.Value)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", node.Value, err)
	}
	d.Duration = v
	return nil
}

func Load(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()
	return Decode(f)
}

func Decode(r io.Reader) (Config, error) {
	c := defaults()
	dec := yaml.NewDecoder(io.LimitReader(r, 1<<20))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

func defaults() Config {
	return Config{
		Server:  Server{Address: ":8080", ShutdownTimeout: Duration{10 * time.Second}},
		Webhook: Webhook{SecretEnv: "GROUPBRIDGE_WEBHOOK_SECRET", MaxSkew: Duration{5 * time.Minute}},
		Source:  Source{Type: "keycloak", ClientSecretEnv: "GROUPBRIDGE_KEYCLOAK_CLIENT_SECRET", PollInterval: Duration{30 * time.Second}},
		State:   State{Path: "/var/lib/groupbridge/state.json"},
	}
}

func (c Config) Validate() error {
	var errs []error
	if c.Server.Address == "" {
		errs = append(errs, errors.New("server.address is required"))
	}
	if c.Server.ShutdownTimeout.Duration <= 0 {
		errs = append(errs, errors.New("server.shutdownTimeout must be positive"))
	}
	if c.Webhook.SecretEnv == "" || c.Webhook.MaxSkew.Duration <= 0 {
		errs = append(errs, errors.New("webhook.secretEnv and a positive webhook.maxSkew are required"))
	}
	if c.Source.Type != "keycloak" {
		errs = append(errs, fmt.Errorf("source.type must be keycloak, got %q", c.Source.Type))
	}
	if c.Source.BaseURL == "" || c.Source.Realm == "" || c.Source.ClientID == "" || c.Source.ClientSecretEnv == "" {
		errs = append(errs, errors.New("source.baseURL, realm, clientID, and clientSecretEnv are required"))
	}
	if err := validateBaseURL(c.Source.BaseURL, c.Source.AllowInsecureHTTP); err != nil {
		errs = append(errs, fmt.Errorf("source.baseURL: %w", err))
	}
	if c.Source.PollInterval.Duration <= 0 {
		errs = append(errs, errors.New("source.pollInterval must be positive"))
	}
	targets := make(map[string]Target, len(c.Targets))
	for i, t := range c.Targets {
		if t.Name == "" || t.Type == "" || t.BaseURL == "" {
			errs = append(errs, fmt.Errorf("targets[%d] requires name, type, and baseURL", i))
		}
		if t.Type != "gitlab" && t.Type != "vault" {
			errs = append(errs, fmt.Errorf("targets[%d].type %q is not compiled in", i, t.Type))
		}
		switch t.Type {
		case "gitlab":
			if t.TokenEnv == "" {
				errs = append(errs, fmt.Errorf("targets[%d] GitLab target requires tokenEnv", i))
			}
			if t.OIDCMount != "" || t.KVMount != "" || t.KubernetesAuth != (VaultKubernetesAuth{}) {
				errs = append(errs, fmt.Errorf("targets[%d] contains Vault-only fields", i))
			}
		case "vault":
			if t.TokenEnv != "" || t.ResolverTokenEnv != "" {
				errs = append(errs, fmt.Errorf("targets[%d] Vault target must not use tokenEnv or resolverTokenEnv", i))
			}
			if !safeVaultPath(t.OIDCMount) || !safeVaultPath(t.KVMount) || !safeVaultPath(t.KubernetesAuth.Mount) {
				errs = append(errs, fmt.Errorf("targets[%d] Vault mounts must be a safe mount path", i))
			}
			if t.KubernetesAuth.Role == "" || !strings.HasPrefix(t.KubernetesAuth.TokenFile, "/") {
				errs = append(errs, fmt.Errorf("targets[%d] Vault kubernetesAuth requires role and absolute tokenFile", i))
			}
			if t.OIDCProvider != "" {
				errs = append(errs, fmt.Errorf("targets[%d] contains GitLab-only fields", i))
			}
		}
		if err := validateBaseURL(t.BaseURL, t.AllowInsecureHTTP); err != nil {
			errs = append(errs, fmt.Errorf("targets[%d].baseURL: %w", i, err))
		}
		if _, exists := targets[t.Name]; exists {
			errs = append(errs, fmt.Errorf("duplicate target name %q", t.Name))
		}
		targets[t.Name] = t
	}
	if len(c.Targets) == 0 {
		errs = append(errs, errors.New("at least one target is required"))
	}
	ruleNames := make(map[string]struct{}, len(c.Rules))
	for i, r := range c.Rules {
		if r.Name == "" || !strings.HasPrefix(r.SourceGroupPrefix, "/") || r.TargetProvider == "" {
			errs = append(errs, fmt.Errorf("rules[%d] requires name, absolute sourceGroupPrefix, and targetProvider", i))
		}
		if _, exists := ruleNames[r.Name]; exists {
			errs = append(errs, fmt.Errorf("duplicate rule name %q", r.Name))
		}
		ruleNames[r.Name] = struct{}{}
		pathSet := make(map[string]struct{}, len(r.SourceGroupPaths))
		for _, path := range r.SourceGroupPaths {
			prefix := "/" + strings.Trim(r.SourceGroupPrefix, "/")
			if path == "" || path != "/"+strings.Trim(path, "/") ||
				(prefix != "/" && !strings.HasPrefix(path, prefix+"/")) ||
				(prefix == "/" && path == "/") {
				errs = append(errs, fmt.Errorf("rules[%d].sourceGroupPaths entry %q must be a canonical absolute descendant of sourceGroupPrefix", i, path))
			}
			if _, duplicate := pathSet[path]; duplicate {
				errs = append(errs, fmt.Errorf("rules[%d].sourceGroupPaths contains duplicate %q", i, path))
			}
			pathSet[path] = struct{}{}
		}
		target, ok := targets[r.TargetProvider]
		if !ok {
			errs = append(errs, fmt.Errorf("rules[%d] references unknown target %q", i, r.TargetProvider))
		}
		if r.Prune != "none" && r.Prune != "managed-only" && r.Prune != "authoritative" {
			errs = append(errs, fmt.Errorf("rules[%d].prune must be none, managed-only, or authoritative", i))
		}
		if r.MaxRemovals < 0 {
			errs = append(errs, fmt.Errorf("rules[%d].maxRemovals cannot be negative", i))
		}
		if ok {
			declaredTargets := make(map[string]string, len(r.SourceGroupPaths))
			for _, sourcePath := range r.SourceGroupPaths {
				targetPath, mapErr := declaredTargetPath(target.Type, r, sourcePath)
				if mapErr != nil {
					errs = append(errs, fmt.Errorf("rules[%d].sourceGroupPaths entry %q: %w", i, sourcePath, mapErr))
					continue
				}
				if previous, collision := declaredTargets[targetPath]; collision {
					errs = append(errs, fmt.Errorf("rules[%d].sourceGroupPaths entries %q and %q collide at target path %q", i, previous, sourcePath, targetPath))
				}
				declaredTargets[targetPath] = sourcePath
			}
			switch target.Type {
			case "gitlab":
				if r.Vault != nil {
					errs = append(errs, fmt.Errorf("rules[%d] GitLab rule must not contain vault", i))
				}
				if _, valid := accessLevels[r.AccessLevel]; !valid {
					errs = append(errs, fmt.Errorf("rules[%d].accessLevel is invalid", i))
				}
				if len(r.IdentityMatch) == 0 {
					errs = append(errs, fmt.Errorf("rules[%d].identityMatch must not be empty", i))
				}
				for _, match := range r.IdentityMatch {
					if match != "oidc" && match != "username" && match != "email" {
						errs = append(errs, fmt.Errorf("rules[%d].identityMatch contains unsupported value %q", i, match))
					}
					if match == "oidc" && (target.OIDCProvider == "" || target.ResolverTokenEnv == "") {
						errs = append(errs, fmt.Errorf("rules[%d] uses oidc matching but target %q lacks oidcProvider or resolverTokenEnv", i, target.Name))
					}
				}
			case "vault":
				if r.Vault == nil || !safeVaultPath(r.Vault.PathPrefix) {
					errs = append(errs, fmt.Errorf("rules[%d] Vault rule requires vault.pathPrefix as a safe mount path", i))
				} else if r.Vault.AccessProfile != "viewer" && r.Vault.AccessProfile != "editor" {
					errs = append(errs, fmt.Errorf("rules[%d] Vault accessProfile must be viewer or editor", i))
				}
				if r.Vault != nil && r.Vault.PolicyMode != "" && r.Vault.PolicyMode != "verify-only" {
					errs = append(errs, fmt.Errorf("rules[%d] Vault policyMode must be verify-only", i))
				}
				if r.Prune != "none" {
					errs = append(errs, fmt.Errorf("rules[%d] read-only Vault target requires prune none", i))
				}
				if r.TargetParent != "" || r.AccessLevel != "" || len(r.IdentityMatch) != 0 ||
					len(r.ProtectedUsers) != 0 || r.MaxRemovals != 0 || r.EnforceAccessLevel ||
					r.CreateGroups || r.AdoptExistingGroup {
					errs = append(errs, fmt.Errorf("rules[%d] Vault rule contains GitLab-only fields", i))
				}
			}
		}
	}
	if len(c.Rules) == 0 {
		errs = append(errs, errors.New("at least one rule is required"))
	}
	if c.State.Path == "" {
		errs = append(errs, errors.New("state.path is required"))
	}
	return errors.Join(errs...)
}

var unsafeDeclaredPathChars = regexp.MustCompile(`[^a-z0-9_-]+`)

func declaredTargetPath(targetType string, rule Rule, sourcePath string) (string, error) {
	prefix := "/" + strings.Trim(rule.SourceGroupPrefix, "/")
	relative := strings.TrimPrefix(sourcePath, "/")
	if prefix != "/" {
		relative = strings.TrimPrefix(sourcePath, prefix+"/")
	}
	var mapped []string
	for _, segment := range strings.Split(relative, "/") {
		switch targetType {
		case "vault":
			if len(segment) == 0 || len(segment) > 63 {
				return "", fmt.Errorf("Vault path segment %q is unsafe", segment)
			}
			for _, ch := range segment {
				if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
					(ch >= '0' && ch <= '9') || ch == '-' || ch == '_') {
					return "", fmt.Errorf("Vault path segment %q is unsafe", segment)
				}
			}
			mapped = append(mapped, strings.ToLower(segment))
		case "gitlab":
			slug := strings.Trim(unsafeDeclaredPathChars.ReplaceAllString(strings.ToLower(segment), "-"), "-_")
			if slug == "" {
				return "", fmt.Errorf("group path segment %q has no target-safe characters", segment)
			}
			mapped = append(mapped, slug)
		}
	}
	parent := rule.TargetParent
	if targetType == "vault" && rule.Vault != nil {
		parent = rule.Vault.PathPrefix
	}
	return strings.Trim(strings.Trim(parent, "/")+"/"+strings.Join(mapped, "/"), "/"), nil
}

func safeVaultPath(value string) bool {
	if value == "" || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
		for _, r := range segment {
			if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
				return false
			}
		}
	}
	return true
}

func Secret(envName string) (string, error) {
	v, ok := os.LookupEnv(envName)
	if !ok || strings.TrimSpace(v) == "" {
		return "", fmt.Errorf("required secret environment variable %s is unset", envName)
	}
	return v, nil
}

func validateBaseURL(raw string, allowInsecure bool) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("must be an absolute http(s) URL without credentials, query, or fragment")
	}
	if u.Scheme != "https" && !allowInsecure {
		return errors.New("must use https unless allowInsecureHTTP is explicitly true")
	}
	return nil
}

var accessLevels = map[string]struct{}{
	"guest": {}, "planner": {}, "reporter": {}, "developer": {}, "maintainer": {},
}
