package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-sdk"
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
	if finding.Kind != sdk.FindingKindPackage || finding.PolicyStatus != sdk.FindingPolicyStatusWarn {
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

// Findings travel to the host as JSON of sdk.Finding. Hosts older than
// bomly-cli v0.20.0 read only the legacy "disposition" field and treat its
// absence as fail, which would silently escalate this auditor's warn findings;
// the manifest therefore requires bomlyVersion >=0.20.0. Pin the wire shape
// the plugin relies on: policy_status carries warn on the way out, and the SDK
// still accepts legacy disposition payloads on the way in.
func TestFindingPolicyStatusWireCompat(t *testing.T) {
	dep := sdk.NewDependency(sdk.Dependency{
		Coordinates: sdk.Coordinates{
			Name:      "left-pad",
			Version:   "1.3.0",
			Ecosystem: sdk.EcosystemNPM,
			PURL:      "pkg:npm/left-pad@1.3.0",
		},
	})
	data, err := json.Marshal(finding(dep, "test reason"))
	if err != nil {
		t.Fatalf("marshal finding: %v", err)
	}
	if !strings.Contains(string(data), `"policy_status":"warn"`) {
		t.Fatalf("serialized finding must carry policy_status warn, got %s", data)
	}

	var roundTrip sdk.Finding
	if err := json.Unmarshal(data, &roundTrip); err != nil {
		t.Fatalf("unmarshal finding: %v", err)
	}
	if roundTrip.PolicyStatus != sdk.FindingPolicyStatusWarn {
		t.Fatalf("round-tripped policy status = %q, want warn", roundTrip.PolicyStatus)
	}

	var legacy sdk.Finding
	if err := json.Unmarshal([]byte(`{"id":"finding","disposition":"warn"}`), &legacy); err != nil {
		t.Fatalf("unmarshal legacy finding: %v", err)
	}
	if legacy.PolicyStatus != sdk.FindingPolicyStatusWarn {
		t.Fatalf("legacy disposition mapped to %q, want warn", legacy.PolicyStatus)
	}
}
