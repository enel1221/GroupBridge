// Package config loads and strictly validates GroupBridge configuration.
package config

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
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
	Name              string `yaml:"name"`
	Type              string `yaml:"type"`
	BaseURL           string `yaml:"baseURL"`
	AllowInsecureHTTP bool   `yaml:"allowInsecureHTTP"`
	TokenEnv          string `yaml:"tokenEnv"`
	ResolverTokenEnv  string `yaml:"resolverTokenEnv"`
	OIDCProvider      string `yaml:"oidcProvider"`
}

type Rule struct {
	Name               string   `yaml:"name"`
	SourceGroupPrefix  string   `yaml:"sourceGroupPrefix"`
	TargetProvider     string   `yaml:"targetProvider"`
	TargetParent       string   `yaml:"targetParent"`
	CreateGroups       bool     `yaml:"createGroups"`
	AdoptExistingGroup bool     `yaml:"adoptExistingGroup"`
	AccessLevel        string   `yaml:"accessLevel"`
	Prune              string   `yaml:"prune"`
	ProtectedUsers     []string `yaml:"protectedUsers"`
	MaxRemovals        int      `yaml:"maxRemovals"`
	IdentityMatch      []string `yaml:"identityMatch"`
	EnforceAccessLevel bool     `yaml:"enforceAccessLevel"`
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
		if t.Name == "" || t.Type == "" || t.BaseURL == "" || t.TokenEnv == "" {
			errs = append(errs, fmt.Errorf("targets[%d] requires name, type, baseURL, and tokenEnv", i))
		}
		if t.Type != "gitlab" {
			errs = append(errs, fmt.Errorf("targets[%d].type %q is not compiled in", i, t.Type))
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
		target, ok := targets[r.TargetProvider]
		if !ok {
			errs = append(errs, fmt.Errorf("rules[%d] references unknown target %q", i, r.TargetProvider))
		}
		if _, ok := accessLevels[r.AccessLevel]; !ok {
			errs = append(errs, fmt.Errorf("rules[%d].accessLevel is invalid", i))
		}
		if r.Prune != "none" && r.Prune != "managed-only" && r.Prune != "authoritative" {
			errs = append(errs, fmt.Errorf("rules[%d].prune must be none, managed-only, or authoritative", i))
		}
		if r.MaxRemovals < 0 {
			errs = append(errs, fmt.Errorf("rules[%d].maxRemovals cannot be negative", i))
		}
		if len(r.IdentityMatch) == 0 {
			errs = append(errs, fmt.Errorf("rules[%d].identityMatch must not be empty", i))
		}
		for _, match := range r.IdentityMatch {
			if match != "oidc" && match != "username" && match != "email" {
				errs = append(errs, fmt.Errorf("rules[%d].identityMatch contains unsupported value %q", i, match))
			}
			if match == "oidc" && ok && (target.OIDCProvider == "" || target.ResolverTokenEnv == "") {
				errs = append(errs, fmt.Errorf("rules[%d] uses oidc matching but target %q lacks oidcProvider or resolverTokenEnv", i, target.Name))
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
