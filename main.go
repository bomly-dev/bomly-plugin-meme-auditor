package main

import (
	"context"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/sdk"
	"github.com/google/uuid"
)

const (
	auditorName = "bomly.meme.auditor"
)

type auditor struct{}

type config struct {
	ExtraPackages []string `json:"extra_packages"`
}

var defaultMemePackages = map[string]string{
	"colors":         "terminal color chaos is part of the Node.js folklore canon",
	"faker":          "an incident-shaped package name with demo value",
	"is-even":        "if this exists, `is-odd` is probably nearby",
	"is-number":      "micro-package maximalism detected",
	"is-odd":         "the classic dependency-discourse punchline",
	"left-pad":       "the ancient scroll every package manager remembers",
	"noop":           "a package that tells on itself",
	"tiny-invariant": "small enough to summon architecture debate",
}

func (a *auditor) Descriptor(context.Context) (*sdk.AuditorDescriptor, error) {
	return &sdk.AuditorDescriptor{
		Name:        auditorName,
		DisplayName: "Meme Dependency Auditor",
		Aliases:     []string{"meme-auditor", "meme"},
		Tags:        []string{"policy", "dependency-lore"},
	}, nil
}

func (a *auditor) Ready(context.Context, *sdk.AuditRequest) (*sdk.ReadyResponse, error) {
	_, err := loadConfig()
	if err != nil {
		return nil, err
	}
	return &sdk.ReadyResponse{Ready: true}, nil
}

func (a *auditor) Applicable(_ context.Context, req *sdk.AuditRequest) (*sdk.ApplicableResponse, error) {
	if req.Graph == nil {
		return &sdk.ApplicableResponse{Applicable: false}, nil
	}
	return &sdk.ApplicableResponse{Applicable: true}, nil
}

func (a *auditor) Audit(_ context.Context, req *sdk.AuditRequest) (*sdk.AuditResponse, error) {
	if req.Graph == nil {
		return &sdk.AuditResponse{AuditorRuns: []string{auditorName}}, nil
	}
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}
	memePackages := configuredMemePackages(cfg)
	findings := make([]sdk.Finding, 0)
	nodes := req.Graph.Nodes()
	if req.Target != nil {
		nodes = []*sdk.Dependency{req.Target}
	}
	for _, dep := range nodes {
		if dep == nil {
			continue
		}
		key := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(dep.DisplayName()), "@"))
		key = strings.TrimPrefix(key, strings.TrimSpace(dep.Org)+"/")
		reason, ok := memePackages[key]
		if !ok {
			continue
		}
		findings = append(findings, finding(dep, reason))
	}
	return &sdk.AuditResponse{
		Findings:        findings,
		AuditorRuns:     []string{auditorName},
		AuditorFindings: map[string]int{auditorName: len(findings)},
	}, nil
}

func loadConfig() (config, error) {
	var cfg config
	if err := sdk.DecodePluginConfigFromEnv(&cfg); err != nil {
		return config{}, err
	}
	return cfg, nil
}

func configuredMemePackages(cfg config) map[string]string {
	out := make(map[string]string, len(defaultMemePackages)+len(cfg.ExtraPackages))
	for name, reason := range defaultMemePackages {
		out[name] = reason
	}
	for _, name := range cfg.ExtraPackages {
		name = strings.ToLower(strings.TrimSpace(name))
		if name != "" {
			out[name] = "configured as local dependency lore"
		}
	}
	return out
}

func finding(dep *sdk.Dependency, reason string) sdk.Finding {
	purl := dep.PackageRef
	if purl == "" {
		purl = sdk.CanonicalPackageURLFromDependency(dep)
	}
	reasons := []string{"meme-dependency", reason}
	sort.Strings(reasons)
	return sdk.Finding{
		ID:             newFindingID(),
		Kind:           sdk.FindingKindPackage,
		Title:          "Dependency has unusually high meme density",
		Severity:       "low",
		Source:         auditorName,
		Auditor:        auditorName,
		Disposition:    sdk.FindingDispositionWarn,
		PackageRef:     purl,
		DependencyRefs: []string{dep.ID},
		Reasons:        reasons,
	}
}

func newFindingID() string {
	id, err := uuid.NewRandom()
	if err != nil {
		return auditorName
	}
	return id.String()
}

func main() {
	sdk.ServeAuditor(&auditor{})
}
