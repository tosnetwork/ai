package nativecore

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The contract-execution vectors are published twice: in testdata, where the
// conformance tests of this package and of the reference codec read them, and
// under spec/test-vectors as the normative copy that SERVICE_ACTOR_TVM_V1
// names. Both are copies of the tos sandbox fixture and must stay identical.
func TestSpecServiceActorVectorsEqualTestdata(t *testing.T) {
	local, err := os.ReadFile(filepath.Join("testdata", "service-actor-conformance-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	spec, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "test-vectors", "service-actor-conformance-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(local) == 0 || !bytes.Equal(local, spec) {
		t.Fatal("spec/test-vectors/service-actor-conformance-vectors.json differs from the testdata copy")
	}
}
