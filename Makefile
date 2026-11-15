.PHONY: verify fmt-check proto-check vet test-race build conformance boundary-lint spec-check fuzz test-privileged \
	messenger-test-adnl messenger-test-openmls messenger-sandbox messenger-vectors messenger-cross-build messenger-fuzz

verify: fmt-check proto-check vet test-race build conformance boundary-lint spec-check \
	messenger-test-adnl messenger-test-openmls messenger-sandbox messenger-vectors

fmt-check:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; exit 1; }

# The committed generated code must equal what the pinned generator emits,
# and the normative schema in spec/ must compile to the same descriptor as
# the generator input in protocol/ apart from go_package.
proto-check:
	GOWORK=off protocol/scripts/test-native-proto-generated.sh
	GOWORK=off scripts/check-proto-descriptors.sh

vet:
	GOWORK=off go vet ./...

test-race:
	GOWORK=off go test -race -count=1 ./...

build:
	GOWORK=off go build ./...

# The committed Guarantor conformance corpus must equal what the generator
# emits (compared, never rewritten), and an independent verifier must
# reproduce its registries, digests and native authorization vectors.
GUARANTOR_CORPUS := protocol/tests/conformance/agent-guarantor-v1.json
GUARANTOR_SIGNATURE_VECTOR := protocol/pkg/agentguarantor/testdata/agent-guarantor-signature-vector.json

conformance:
	GOWORK=off go run ./protocol/cmd/agent-guarantor-fixtures -signature-vector $(GUARANTOR_SIGNATURE_VECTOR) | cmp - $(GUARANTOR_CORPUS)
	python3 -I protocol/tests/conformance/agent_guarantor_registry_verify.py < $(GUARANTOR_CORPUS)

# gateway/ must not import execution/; protocol/ imports neither; messenger/
# imports protocol/ only; nothing imports messenger/.
boundary-lint:
	GOWORK=off scripts/check-boundaries.sh

# The closed PredictionMarket V1 release manifest must match its vectors.
spec-check:
	python3 spec/scripts/verify-prediction-market-compatibility.py

# Bounded native fuzzing of the strict PredictionMarket decoders; the regular
# suite runs the fixed seeds. The budget is an execution count, not a
# duration: a duration-bounded run can end with a spurious "context deadline
# exceeded" failure when the fuzz coordinator observes its deadline before the
# worker context derived from it is canceled. A count-bounded run stops on the
# count with no deadline involved. One million executions is roughly the
# thirty-second budget on a four-core CI runner.
FUZZ_EXECUTIONS ?= 1000000
fuzz:
	GOWORK=off go test ./protocol/pkg/predictionmarket -run '^$$' -fuzz '^FuzzPredictionDecoders$$' -fuzztime=$(FUZZ_EXECUTIONS)x

# The executor service's privileged suite: needs passwordless sudo and the
# private containerd. Opt-in; not part of verify.
test-privileged:
	$(MAKE) -C execution test-privileged

# --- messenger/ -----------------------------------------------------------

# The ADNL gateway cannot run under the race detector (tosutils-go's TL
# serializer trips checkptr), so its ADNL and RLDP end-to-end tests skip in
# test-race and run here.
messenger-test-adnl:
	GOWORK=off go test -count=1 -run 'ADNL|RLDP' ./messenger/pkg/probe ./messenger/pkg/publicchannel ./messenger/cmd/tos-reachability

OPENMLS_DRIVER_MANIFEST := messenger/rust/openmls-driver/Cargo.toml

messenger-test-openmls:
	cargo fmt --manifest-path $(OPENMLS_DRIVER_MANIFEST) -- --check
	cargo test --locked --manifest-path $(OPENMLS_DRIVER_MANIFEST)
	cargo build --locked --manifest-path $(OPENMLS_DRIVER_MANIFEST)
	TOS_OPENMLS_DRIVER="$(CURDIR)/messenger/rust/openmls-driver/target/debug/tos-openmls-driver" GOWORK=off go test -count=1 -run OpenMLS ./messenger/pkg/group ./messenger/pkg/eventlog ./messenger/pkg/mlslab

# The attachment scanner sandbox tests skip when bubblewrap, prlimit,
# systemd-run or a user systemd manager is missing. Here they must run: a
# skip fails. The host must allow unprivileged user namespaces for the
# scanner's staged bubblewrap (on Ubuntu with AppArmor:
# kernel.apparmor_restrict_unprivileged_userns=0).
MESSENGER_SANDBOX_TESTS := ^(TestOpenForAgentRequiresPinnedSandboxedScanner|TestScannerResourcesAreCopiedReadOnlyAndVerdictBound|TestScannerCgroupHardLimitsLive|TestScannerSandboxCannotReadUnboundHostFile)$$
messenger-sandbox:
	GOWORK=off scripts/check-messenger-sandbox.sh '$(MESSENGER_SANDBOX_TESTS)'

# Vectors are what a second implementation checks itself against, so a
# change to one has to be deliberate rather than incidental.
messenger-vectors:
	GOWORK=off go test ./messenger/internal/vectors -count=1
	git diff --exit-code messenger/internal/vectors/testdata

# A single-writer journal, a UDP probe, and a binary DHT value all have
# assumptions about word size and endianness that only another architecture
# can disprove.
MESSENGER_CROSS_TARGETS := linux/amd64 linux/arm64 linux/arm linux/riscv64 darwin/arm64
messenger-cross-build:
	GOWORK=off scripts/messenger-cross-build.sh $(MESSENGER_CROSS_TARGETS)

# Native fuzzing of every Fuzz target in these packages. The budget is an
# execution count per target, not a duration (see FUZZ_EXECUTIONS above). Two
# million executions is above what every target reached in the former
# repository's 60-second runs (at most 1.83 million). A target that stalls now
# runs into the CI job timeout and fails, where a duration budget let it pass
# after a handful of executions.
MESSENGER_FUZZ_PACKAGES ?= ./messenger/pkg/identity ./messenger/pkg/directory ./messenger/pkg/envelope \
	./messenger/pkg/probe ./messenger/pkg/fault ./messenger/pkg/attachments ./messenger/pkg/attachmentapi \
	./messenger/pkg/attachmentops
MESSENGER_FUZZ_EXECUTIONS ?= 2000000
messenger-fuzz:
	GOWORK=off scripts/messenger-fuzz.sh $(MESSENGER_FUZZ_EXECUTIONS) $(MESSENGER_FUZZ_PACKAGES)
