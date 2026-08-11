package plugin

import (
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	sdk "github.com/bomly-dev/bomly-sdk"
	"github.com/bomly-dev/bomly-sdk/conformance"
	"go.uber.org/zap"
)

// testHost is a minimal HostContext for unit tests.
type testHost struct {
	config json.RawMessage
}

func (h testHost) Logger() *zap.Logger                 { return zap.NewNop() }
func (h testHost) HTTPClient() *sdk.HTTPClientProvider { return nil }
func (h testHost) Runtime() sdk.RuntimeInfo {
	return sdk.RuntimeInfo{Execution: sdk.ExecutionEmbedded}
}

func (h testHost) DecodeConfig(v any) error {
	payload := h.config
	if len(payload) == 0 {
		payload = json.RawMessage("{}")
	}
	return json.Unmarshal(payload, v)
}

func newAuditor(t *testing.T, config json.RawMessage) sdk.Auditor {
	t.Helper()
	auditor, err := Module().Auditor.New(context.Background(), testHost{config: config})
	if err != nil {
		t.Fatalf("construct auditor: %v", err)
	}
	return auditor
}

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
	resp, err := newAuditor(t, nil).Audit(context.Background(), sdk.AuditRequest{Graph: graph})
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

func TestAuditFlagsConfiguredExtraPackage(t *testing.T) {
	graph := sdk.New()
	dep := sdk.NewDependency(sdk.Dependency{
		Coordinates: sdk.Coordinates{
			Name:      "hyperfast-ai-agent",
			Version:   "0.0.1",
			Ecosystem: sdk.EcosystemNPM,
			PURL:      "pkg:npm/hyperfast-ai-agent@0.0.1",
		},
	})
	if err := graph.AddNode(dep); err != nil {
		t.Fatalf("AddNode() error = %v", err)
	}
	auditor := newAuditor(t, json.RawMessage(`{"extra_packages":["Hyperfast-AI-Agent"]}`))
	resp, err := auditor.Audit(context.Background(), sdk.AuditRequest{Graph: graph})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(resp.Findings) != 1 {
		t.Fatalf("expected one finding for the configured package, got %#v", resp.Findings)
	}
}

// A config block that does not decode must surface through Ready as the
// not-ready reason instead of failing construction, so the host can report
// it (the ReadyResponse.Reason contract from the legacy serving style).
func TestInvalidConfigSurfacesThroughReady(t *testing.T) {
	auditor := newAuditor(t, json.RawMessage(`{"extra_packages":"not-a-list"}`))
	if err := auditor.Ready(context.Background(), sdk.AuditRequest{}); err == nil {
		t.Fatal("expected Ready to report the invalid configuration")
	}
	if _, err := auditor.Audit(context.Background(), sdk.AuditRequest{Graph: sdk.New()}); err == nil {
		t.Fatal("expected Audit to refuse to run with an invalid configuration")
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

// TestConformance runs the SDK conformance suite against the module,
// including the bomly-plugin.json identity cross-check.
func TestConformance(t *testing.T) {
	conformance.Test(t, conformance.Config{
		Module:       Module(),
		ManifestPath: filepath.Join("..", "bomly-plugin.json"),
		SampleConfig: json.RawMessage(`{"extra_packages":["hyperfast-ai-agent"]}`),
	})
}

// TestProbeBinary builds the real plugin binary and probes it over the
// managed HashiCorp gRPC transport, asserting the served descriptor equals
// the in-process one.
func TestProbeBinary(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not available; skipping managed-transport probe")
	}
	binaryPath := filepath.Join(t.TempDir(), "bomly-plugin-meme-auditor")
	build := exec.Command(goBinary, "build", "-o", binaryPath, "./cmd/bomly-plugin-meme-auditor")
	build.Dir = ".."
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build plugin binary: %v\n%s", err, output)
	}
	conformance.ProbeBinary(t, binaryPath, conformance.WithModule(Module()))
}
