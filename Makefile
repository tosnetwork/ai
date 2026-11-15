.PHONY: verify fmt-check proto-check vet test-race build conformance boundary-lint spec-check fuzz test-privileged

verify: fmt-check proto-check vet test-race build conformance boundary-lint spec-check

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

# gateway/ must not import execution/; protocol/ imports neither.
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
