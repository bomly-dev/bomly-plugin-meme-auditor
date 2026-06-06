package main

import (
	"context"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestAuditFlagsMemeDependency(t *testing.T) {
	graph := sdk.New()
	dep := sdk.NewDependency(sdk.Dependency{
		Name:      "left-pad",
		Version:   "1.3.0",
		Ecosystem: string(sdk.EcosystemNPM),
		PURL:      "pkg:npm/left-pad@1.3.0",
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
}
