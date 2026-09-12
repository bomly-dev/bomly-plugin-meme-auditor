// Package plugin implements the meme dependency auditor: an example Bomly
// AUDITOR that emits low-severity warn findings for dependency names with a
// well-earned place in package-manager folklore.
package plugin

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-sdk"
	"github.com/google/uuid"
)

// Name is the plugin's identity. It MUST equal the "id" field in
// bomly-plugin.json — Bomly refuses to load a plugin whose manifest id and
// runtime descriptor name disagree.
const Name = "bomly.meme.auditor"

// Auditor is the component. Configuration is decoded once at construction
// through the HostContext; a decode failure is remembered and surfaced
// through Ready so the host can report the reason instead of hard-failing.
type Auditor struct {
	config    config
	configErr error
}

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

// descriptor is the auditor's static registration data.
func descriptor() sdk.AuditorDescriptor {
	return sdk.AuditorDescriptor{
		Name:         Name,
		DisplayName:  "Meme Dependency Auditor",
		Aliases:      []string{"meme-auditor", "meme"},
		Tags:         []string{"policy", "dependency-lore"},
		ConfigSchema: sdk.MustConfigSchemaFor(config{}),
	}
}

// Descriptor identifies the auditor to Bomly.
func (a *Auditor) Descriptor() sdk.AuditorDescriptor { return descriptor() }

// Ready reports whether the auditor can run; an invalid configuration is
// reported as the not-ready reason rather than a construction failure.
func (a *Auditor) Ready(context.Context, sdk.AuditRequest) error {
	if a.configErr != nil {
		return fmt.Errorf("invalid meme auditor configuration: %w", a.configErr)
	}
	return nil
}

// Applicable reports whether the request carries a dependency graph to audit.
func (a *Auditor) Applicable(_ context.Context, req sdk.AuditRequest) (bool, error) {
	return req.Graph != nil, nil
}

// Audit emits warn findings for dependencies whose names carry meme lore.
func (a *Auditor) Audit(_ context.Context, req sdk.AuditRequest) (sdk.AuditResult, error) {
	// Refuse to run on invalid configuration before any fast path, so a
	// nil graph cannot mask a broken config as a silent success.
	if a.configErr != nil {
		return sdk.AuditResult{}, fmt.Errorf("invalid meme auditor configuration: %w", a.configErr)
	}
	if req.Graph == nil {
		return sdk.AuditResult{AuditorRuns: []string{Name}}, nil
	}
	memePackages := configuredMemePackages(a.config)
	findings := make([]sdk.Finding, 0)
	// Dependency nodes only. Before the SDK's typed node union every graph
	// node was an sdk.Dependency, including the scanned project's own root
	// and workspace members, so this loop audited them too. Ownership is now
	// the node kind, and this auditor is about consumed packages: the
	// findings it emits carry a PackageRef, which a module or manifest node
	// has no business supplying.
	nodes := req.Graph.DependencyNodes()
	if req.Target != nil {
		nodes = []*sdk.DependencyNode{req.Target}
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
	return sdk.AuditResult{
		Findings:        findings,
		AuditorRuns:     []string{Name},
		AuditorFindings: map[string]int{Name: len(findings)},
	}, nil
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

func finding(dep *sdk.DependencyNode, reason string) sdk.Finding {
	// A dependency node's identity is its canonical package URL, and
	// PackageRef is derived from it by the constructor, so the two agree by
	// construction. The fallback is kept because PackageRef is a plain wire
	// field a producer can leave empty.
	purl := dep.PackageRef
	if purl == "" {
		purl = sdk.NodePURL(dep)
	}
	reasons := []string{"meme-dependency", reason}
	sort.Strings(reasons)
	return sdk.Finding{
		ID:             newFindingID(),
		Kind:           sdk.FindingKindPackage,
		Title:          "Dependency has unusually high meme density",
		Severity:       sdk.SeverityLow,
		Source:         Name,
		Auditor:        Name,
		PolicyStatus:   sdk.FindingPolicyStatusWarn,
		PackageRef:     purl,
		DependencyRefs: []string{dep.NodeID()},
		Reasons:        reasons,
	}
}

func newFindingID() string {
	id, err := uuid.NewRandom()
	if err != nil {
		return Name
	}
	return id.String()
}

// Module packages the auditor for both execution modes: Bomly can embed it
// in-process or serve it as a managed plugin subprocess (see
// cmd/bomly-plugin-meme-auditor).
func Module() sdk.Module {
	return sdk.Module{
		Kind: sdk.PluginKindAuditor,
		Auditor: &sdk.AuditorModule{
			Descriptor: descriptor(),
			New: func(_ context.Context, host sdk.HostContext) (sdk.Auditor, error) {
				auditor := &Auditor{}
				auditor.configErr = host.DecodeConfig(&auditor.config)
				return auditor, nil
			},
		},
	}
}
