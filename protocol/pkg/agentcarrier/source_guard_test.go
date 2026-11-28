package agentcarrier

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func guardSource(raw []byte) bool {
	f, err := parser.ParseFile(token.NewFileSet(), "source.go", raw, 0)
	if err != nil {
		return false
	}
	aliases := map[string]bool{}
	for _, i := range f.Imports {
		path, err := strconv.Unquote(i.Path.Value)
		if err != nil {
			return false
		}
		if strings.Contains(path, "/messenger/") {
			return false
		}
		if path != "github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay" {
			continue
		}
		name := "agentpacketrelay"
		if i.Name != nil {
			name = i.Name.Name
		}
		if name == "." || name == "_" {
			return false
		}
		aliases[name] = true
	}
	valid := true
	allowed := map[string]bool{"MailboxPolicy": true, "HintIndexEntry": true, "V2Client": true, "NewV2Client": true, "V2Description": true, "V2MailboxEntry": true, "StatusError": true, "RetryAfter": true, "MinEnvelopeBytes": true}
	ast.Inspect(f, func(n ast.Node) bool {
		if s, ok := n.(*ast.SelectorExpr); ok {
			if id, ok := s.X.(*ast.Ident); ok && aliases[id.Name] && !allowed[s.Sel.Name] {
				valid = false
			}
		}
		return true
	})
	return valid
}
func TestCarrierSourceHasNoRetiredRelayClientOrForbiddenImport(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if !guardSource(raw) {
			t.Fatal("forbidden carrier dependency", file)
		}
		checked++
	}
	if checked < 8 {
		t.Fatal("source guard did not inspect the carrier")
	}
}
func TestCarrierGuardRefusesAliasesAndLegacyObjects(t *testing.T) {
	for _, selector := range []string{"Client", "NewClient", "Mailbox", "RelayDescription"} {
		source := []byte("package x\n import old \"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay\"\n var _ = old." + selector)
		if guardSource(source) {
			t.Fatal("retired API escaped the guard", selector)
		}
	}
	if guardSource([]byte("package x\n import _ \"github.com/tosnetwork/ai/messenger/pkg/identity\"")) {
		t.Fatal("forbidden import escaped")
	}
	if !guardSource([]byte("package x\n import r \"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay\"\n var _ *r.V2Client")) {
		t.Fatal("V2 alias refused")
	}
}
