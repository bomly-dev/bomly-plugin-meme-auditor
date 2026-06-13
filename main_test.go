package main

import (
	"context"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestAuditFlagsMemeDependency(t *testing.T) {
	graph := sdk.New()
	dep := sdk.NewDependency(sdk.Dependency{
		Coordinates: sdk.Coordinates{
			Name:      "left-pad",
			Version:   "1.3.0",
			Ecosystem: sdk.EcosystemNPM,
			PURL:      "pkg:npm/left-pad@1.3.0",
		},
	})
	if err := graph.AddNode(dep); err != nil {
		t.Fatalf("AddNode() error = %v", err)
	}
	resp, err := (&auditor{}).Audit(context.Background(), &sdk.AuditRequest{Graph: graph})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(resp.Findings) != 1 {
		t.Fatalf("expected one finding, got %#v", resp.Findings)
	}
	finding := resp.Findings[0]
	if finding.Kind != sdk.FindingKindPackage || finding.Disposition != sdk.FindingDispositionWarn {
		t.Fatalf("unexpected finding %#v", finding)
	}
	if finding.PackageRef != "pkg:npm/left-pad@1.3.0" {
		t.Fatalf("unexpected package ref %q", finding.PackageRef)
	}
	if len(finding.ID) != 36 {
		t.Fatalf("expected UUID finding id, got %q", finding.ID)
	}
	if strings.Count(finding.ID, "-") != 4 {
		t.Fatalf("expected UUID finding id, got %q", finding.ID)
	}
}
