package agentguarantor

import (
	"go/ast"
	"sync"
	"testing"
)

// concurrentRegistryDigests asks digest for the registry digest from callers
// goroutines released together, and returns what each one got.
func concurrentRegistryDigests(digest func() (string, error), callers int) ([]string, []error) {
	digests, errs := make([]string, callers), make([]error, callers)
	start := make(chan struct{})
	var group sync.WaitGroup
	for index := 0; index < callers; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			<-start
			digests[index], errs[index] = digest()
		}(index)
	}
	close(start)
	group.Wait()
	return digests, errs
}

// TestMutationRegistryDigestIsComputedOnceAndUnchanged: the cached mutation
// registry digest is the digest a fresh computation gives, for every caller,
// and concurrent first calls of a cache built the same way are safe and agree.
// The goroutines here only read the registry digest; they do not touch the
// verifier seams.
func TestMutationRegistryDigestIsComputedOnceAndUnchanged(t *testing.T) {
	fresh, err := computeMutationVerifierRegistryDigestV1()
	if err != nil || !validDigest(fresh) {
		t.Fatalf("the mutation registry digest does not compute: %q, %v", fresh, err)
	}
	// Other tests of the package may already have asked the package's cache,
	// so the first calls are raced on a cache constructed exactly as it is.
	first := sync.OnceValues(computeMutationVerifierRegistryDigestV1)
	for name, digest := range map[string]func() (string, error){
		"a new cache, first calls": first, "the package cache": MutationVerifierRegistryDigestV1} {
		digests, errs := concurrentRegistryDigests(digest, 64)
		for index := range digests {
			if errs[index] != nil || digests[index] != fresh {
				t.Fatalf("%s: caller %d got %q, %v; a fresh computation gives %q", name, index, digests[index], errs[index], fresh)
			}
		}
	}
	again, err := computeMutationVerifierRegistryDigestV1()
	if err != nil || again != fresh {
		t.Fatalf("a second fresh computation gives %q, %v, not %q", again, err, fresh)
	}
	binding := testStageAuthorityBinding(t)
	if err := ValidateStageActionAuthorityBindingV1(binding); err != nil {
		t.Fatalf("a stage authority binding built on the cached digest is refused: %v", err)
	}
	for _, stage := range binding.Stages {
		operation, err := StageOperationBindingForAuthorityV1(stage)
		if err != nil || operation.OperationRegistryProfile.ProfileDigest != fresh {
			t.Fatalf("stage %s does not carry the registry digest: %q, %v", stage.Stage, operation.OperationRegistryProfile.ProfileDigest, err)
		}
	}
}

// TestMutationRegistryDigestCacheIsOnlyCalled: the registry digest cache is a
// package variable, so it could be reassigned to return another digest. In
// the package's non-test files it appears once as its declaration, initialized
// with the real computation, and once as the function its accessor calls. No
// test file names it at all, so it cannot serve as a test seam.
func TestMutationRegistryDigestCacheIsOnlyCalled(t *testing.T) {
	const cache = "mutationVerifierRegistryDigestOnceV1"
	declarations, calls := 0, 0
	for _, use := range packageSeamUses(t, cache, false) {
		switch {
		case isPackageVarDeclarationName(use):
			declarations++
			spec := use.parents[0].(*ast.ValueSpec)
			if len(spec.Values) != 1 || !isOnceValuesOf(spec.Values[0], "computeMutationVerifierRegistryDigestV1") {
				t.Errorf("%s: the registry digest cache is not sync.OnceValues of the real computation", use.position)
			}
		case len(use.parents) > 0 && isCallee(use.ident, use.parents[0]):
			calls++
		default:
			t.Errorf("%s: the registry digest cache is used other than by calling it", use.position)
		}
	}
	if declarations != 1 || calls != 1 {
		t.Fatalf("the registry digest cache is declared %d times and called %d times, want once each", declarations, calls)
	}
	for _, use := range packageSeamUses(t, cache, true) {
		t.Errorf("%s: a test file names the registry digest cache", use.position)
	}
}

// isOnceValuesOf reports whether node is exactly sync.OnceValues(function).
func isOnceValuesOf(node ast.Expr, function string) bool {
	call, ok := node.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "OnceValues" {
		return false
	}
	receiver, ok := selector.X.(*ast.Ident)
	argument, isIdent := call.Args[0].(*ast.Ident)
	return ok && receiver.Name == "sync" && isIdent && argument.Name == function
}
