.PHONY: verify fmt-check vet test-race build test-privileged

verify: fmt-check vet test-race build

fmt-check:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; exit 1; }

vet:
	GOWORK=off go vet ./...

test-race:
	GOWORK=off go test -race -count=1 ./...

build:
	GOWORK=off go build ./...

# The authoritative privileged suite of the executor service: a real caller
# under another uid, and a real job through the service on the private
# containerd. The test binaries are built as the invoking user and only they
# run as root. It fails, never skips, when root is unavailable.
PRIVATE_CONTAINERD_SOCKET ?= /run/tos-service-containerd/containerd.sock

test-privileged:
	@sudo -n true || { echo "test-privileged needs passwordless sudo"; exit 1; }
	GOWORK=off go test -c -o bin/privileged/executorservice.test ./pkg/executorservice
	GOWORK=off go test -c -o bin/privileged/executord.test ./cmd/software-work-executord
	sudo -n env TOS_AI_PRIVILEGED_TESTS=1 bin/privileged/executorservice.test \
		-test.run '^TestRealCallersAreAdmittedByTheirKernelUID$$' -test.count=1 -test.v
	sudo -n env TOS_AI_EXECUTORD_LIVE_CONTAINERD_SOCKET=$(PRIVATE_CONTAINERD_SOCKET) bin/privileged/executord.test \
		-test.run '^TestLiveServiceRunsARealJobForAnUnprivilegedCaller$$' -test.count=1 -test.v
