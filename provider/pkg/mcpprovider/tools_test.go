package mcpprovider

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/tosnetwork/ai/provider/pkg/provideragent/agentapi"
	"github.com/tosnetwork/ai/provider/pkg/servicebridge"
)

// silentAgent answers nothing; the schema tests never call a tool.
type silentAgent struct{}

func (silentAgent) Call(context.Context, string, any, any) error {
	return agentapi.Refusal(agentapi.CodeAgentUnavailable, "no agent in this test", nil)
}

func listTools(t *testing.T) []*mcp.Tool {
	t.Helper()
	tools, err := NewTools(Config{Agent: silentAgent{}})
	if err != nil {
		t.Fatal(err)
	}
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ctx := context.Background()
	serverSession, err := NewServer(tools).Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serverSession.Close() })
	session, err := mcp.NewClient(&mcp.Implementation{Name: "schema-test", Version: "1"}, nil).Connect(ctx,
		clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	listed, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	return listed.Tools
}

// The keywords both Claude Code and Codex load (spec section 4.1).
var allowedKeywords = map[string]bool{"type": true, "properties": true, "required": true, "enum": true,
	"minimum": true, "maximum": true, "minLength": true, "maxLength": true, "pattern": true, "description": true,
	"additionalProperties": true}

var allowedTypes = map[string]bool{"object": true, "string": true, "integer": true, "number": true, "boolean": true}

// checkSubset walks one schema as the client receives it, on the wire.
func checkSubset(t *testing.T, where string, schema any) {
	t.Helper()
	object, ok := schema.(map[string]any)
	if !ok {
		t.Errorf("%s: a schema that is not an object: %v", where, schema)
		return
	}
	for key, value := range object {
		if !allowedKeywords[key] {
			t.Errorf("%s: keyword %q is outside the subset", where, key)
			continue
		}
		switch key {
		case "type":
			if name, ok := value.(string); !ok || !allowedTypes[name] {
				t.Errorf("%s: type %v is not one type name", where, value)
			}
		case "properties":
			properties, ok := value.(map[string]any)
			if !ok {
				t.Errorf("%s: properties %v", where, value)
				continue
			}
			for name, property := range properties {
				checkSubset(t, where+"."+name, property)
			}
		case "additionalProperties":
			if value != false {
				t.Errorf("%s: additionalProperties %v is not false", where, value)
			}
		case "required":
			list, ok := value.([]any)
			properties, _ := object["properties"].(map[string]any)
			for _, name := range list {
				if _, present := properties[name.(string)]; !ok || !present {
					t.Errorf("%s: required %v is not a property", where, name)
				}
			}
		case "pattern":
			// The pattern must mean the same in RE2 and in ECMAScript: only
			// anchors, classes, ranges and counted or starred repetition.
			pattern, _ := value.(string)
			if _, err := regexp.Compile(pattern); err != nil || !regexp.MustCompile(`^\^[\[\]A-Za-z0-9_!~ ,{}*\\-]*\$$`).MatchString(pattern) {
				t.Errorf("%s: pattern %q is outside the portable form", where, pattern)
			}
		}
	}
	if object["type"] == "object" && object["additionalProperties"] != false {
		t.Errorf("%s: an object without additionalProperties false", where)
	}
}

// The tool list a client loads: twelve fixed tools, each input an object
// schema in the keyword subset Claude Code and Codex both accept, with its
// output schema in the same subset, constant annotations, and a description
// that says what is untrusted.
func TestTheToolListLoadsInBothClients(t *testing.T) {
	tools := listTools(t)
	want := map[string]bool{ToolStatus: true, ToolRecords: true, ToolPreflight: true, ToolOfferDescribe: true,
		ToolExportOffer: false, ToolPause: false, ToolResume: false, ToolOfferPreview: false, ToolWithdrawPreview: false,
		ToolRequestConfirmation: false, ToolActions: true, ToolCancel: false}
	if len(tools) != len(want) {
		t.Fatalf("%d tools", len(tools))
	}
	for _, tool := range tools {
		readOnly, known := want[tool.Name]
		if !known || tool.Annotations == nil || tool.Annotations.ReadOnlyHint != readOnly ||
			!tool.Annotations.IdempotentHint {
			t.Errorf("tool %s: %+v", tool.Name, tool.Annotations)
		}
		if !readOnly && (tool.Annotations.DestructiveHint == nil || *tool.Annotations.DestructiveHint) {
			t.Errorf("tool %s may be destructive", tool.Name)
		}
		if !strings.HasSuffix(tool.Description, untrustedNote) {
			t.Errorf("tool %s does not say what is untrusted", tool.Name)
		}
		for name, schema := range map[string]any{"input": tool.InputSchema, "output": tool.OutputSchema} {
			raw, err := json.Marshal(schema)
			if err != nil {
				t.Fatal(err)
			}
			var wire any
			if err := json.Unmarshal(raw, &wire); err != nil {
				t.Fatal(err)
			}
			if object, ok := wire.(map[string]any); !ok || object["type"] != "object" {
				t.Errorf("%s %s schema is not an object: %s", tool.Name, name, raw)
			}
			checkSubset(t, tool.Name+" "+name, wire)
		}
	}
}

// The schema's enum of operator states is the node's own.
func TestTheOperatorStatesAreTheNodes(t *testing.T) {
	node := []string{servicebridge.OperatorAdmitted, servicebridge.OperatorExecuting,
		servicebridge.OperatorResultAvailable, servicebridge.OperatorResponded, servicebridge.OperatorRefunded,
		servicebridge.OperatorSwept, servicebridge.OperatorOutcomeUnknown}
	if !slices.Equal(OperatorStates, node) {
		t.Fatalf("%v, not %v", OperatorStates, node)
	}
	states := []string{agentapi.StateAwaitingConfirmation, agentapi.StateCancelled, agentapi.StateDeclined,
		agentapi.StateExpired, agentapi.StateApplying, agentapi.StateApplied, agentapi.StateFailed,
		agentapi.StateAmbiguous}
	if !slices.Equal(ActionStates, states) {
		t.Fatalf("%v, not %v", ActionStates, states)
	}
}

func TestUntrustedTextIsOneEscapedLine(t *testing.T) {
	for input, want := range map[string]string{
		"plain text":         "plain text",
		"two\nlines":         `two\u{000A}lines`,
		"tab\there":          `tab\u{0009}here`,
		"bidi ‮ x":           `bidi \u{202E} x`,
		"bad \xff byte":      "bad � byte",
		"zero​width":         `zero\u{200B}width`,
		"ünïcödé":            "ünïcödé",
		"\x1b[31mred\x1b[0m": `\u{001B}[31mred\u{001B}[0m`,
	} {
		if got := escape(input, MaxUntrustedChars); got != want {
			t.Errorf("escape(%q) = %q, want %q", input, got, want)
		}
	}
	if got := escape(strings.Repeat("a", MaxUntrustedChars+5), MaxUntrustedChars); !strings.HasSuffix(got, truncationMark) ||
		len(got) != MaxUntrustedChars+len(truncationMark) {
		t.Fatalf("a long text: %d bytes", len(got))
	}
}

// The server applies the agent's rules again: the large fields become their
// digest and length, the free-text fields are renamed untrusted_*, and the
// strings under them become untrusted text.
func TestShapeAppliesTheRulesAgain(t *testing.T) {
	answer, err := shape(json.RawMessage(`{"detail":"x","package_base64":"UEFDS0FHRQ==","nested":{"reason":["a","b"]},` +
		`"untrusted_name":"n","balance":18446744073709551615,"kept":"k"}`))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(answer.Structured)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{`"untrusted_detail":{"text":"x"`, `"package_base64_bytes":7`,
		`"untrusted_reason":[{"text":"a"`, `"untrusted_name":{"text":"n"`, `"balance":18446744073709551615`,
		`"kept":"k"`} {
		if !strings.Contains(text, want) {
			t.Errorf("no %s in %s", want, text)
		}
	}
	if strings.Contains(text, "UEFDS0FHRQ==") || strings.Contains(text, `"detail"`) || len(answer.spans) != 4 {
		t.Fatalf("shaped: %s, %d spans", text, len(answer.spans))
	}
}

func TestDeploymentChecksRefuseAReachableCustody(t *testing.T) {
	root, err := os.MkdirTemp("", "pm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(root, "closed"), 0o700); _ = os.RemoveAll(root) })
	socket := filepath.Join(root, "agent.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	openDir := filepath.Join(root, "state")
	if err := os.Mkdir(openDir, 0o700); err != nil {
		t.Fatal(err)
	}
	openRail := filepath.Join(root, "rail.json")
	if err := os.WriteFile(openRail, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	closedDir := filepath.Join(root, "closed")
	if err := os.Mkdir(closedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	closedState, closedRail := filepath.Join(closedDir, "state"), filepath.Join(closedDir, "rail.json")
	if err := os.Mkdir(closedState, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(closedRail, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(closedDir, 0o000); err != nil {
		t.Fatal(err)
	}
	other := uint32(os.Geteuid()) + 1
	good := Deployment{AgentSocket: socket, AgentStateDir: closedState, RailConfig: closedRail, UID: other}
	if os.Geteuid() == 0 {
		t.Skip("root opens every path")
	}
	if err := CheckDeployment(good); err != nil {
		t.Fatalf("a separated deployment: %v", err)
	}
	for name, test := range map[string]struct {
		spoil func(*Deployment)
		want  error
	}{
		"VAULT_URL set":          {func(d *Deployment) { d.Environ = []string{"HOME=/x", "VAULT_URL=file:///v"} }, ErrVaultInEnvironment},
		"the rail's vault env":   {func(d *Deployment) { d.Environ = []string{"RAIL_VAULT=x"}; d.VaultEnvs = []string{"RAIL_VAULT"} }, ErrVaultInEnvironment},
		"a readable state dir":   {func(d *Deployment) { d.AgentStateDir = openDir }, ErrStateReadable},
		"a missing state dir":    {func(d *Deployment) { d.AgentStateDir = filepath.Join(root, "none") }, ErrUnchecked},
		"a readable rail config": {func(d *Deployment) { d.RailConfig = openRail }, ErrRailReadable},
		"a missing rail config":  {func(d *Deployment) { d.RailConfig = filepath.Join(root, "none.json") }, ErrUnchecked},
		"the custody uid":        {func(d *Deployment) { d.UID = uint32(os.Geteuid()) }, ErrRunsAsCustody},
		"no socket":              {func(d *Deployment) { d.AgentSocket = filepath.Join(root, "none.sock") }, ErrSocketMissing},
		"a file for the socket":  {func(d *Deployment) { d.AgentSocket = openRail }, ErrSocketMissing},
	} {
		deployment := good
		test.spoil(&deployment)
		if err := CheckDeployment(deployment); !errors.Is(err, test.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	relative := good
	relative.RailConfig = "rail.json"
	if err := CheckDeployment(relative); err == nil {
		t.Error("a relative path was accepted")
	}
}

func TestTheExportDirectoryIsResolvedAndPrivate(t *testing.T) {
	root := t.TempDir()
	if _, err := NewExportDir("relative"); err == nil {
		t.Error("a relative export directory was accepted")
	}
	open := filepath.Join(root, "open")
	if err := os.Mkdir(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := NewExportDir(open); err == nil {
		t.Error("a world-writable export directory was accepted")
	}
	private := filepath.Join(root, "private")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(private, link); err != nil {
		t.Fatal(err)
	}
	if resolved, err := NewExportDir(link); err != nil || resolved != private {
		t.Fatalf("a link to a private directory: %q %v", resolved, err)
	}
}

func TestAnExportedVersionThatCannotNameAFileIsRefused(t *testing.T) {
	for _, version := range []string{"../x", "a/b", ".hidden", "", strings.Repeat("v", 129)} {
		if _, err := checkExport(agentapi.ExportView{CapabilityID: "cap_" + strings.Repeat("ab", 32),
			CapabilityVersion: version}); err == nil {
			t.Errorf("version %q was accepted", version)
		}
	}
}
