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
# under another uid, a real job through the service on the private
# containerd, and the same job with the daemon and the collection command
# each running in a transient unit under the sandbox of its shipped unit file. The test binaries are built as the invoking user and only they
# run as root. It fails, never skips, when root is unavailable.
PRIVATE_CONTAINERD_SOCKET ?= /run/tos-service-containerd/containerd.sock
PRIVATE_CONTAINERD_NAMESPACE ?= tos-service-paid-work
PRIVATE_IMAGE_DIGEST ?= sha256:9624bca74096f810c5b24e489521dde124fadcfa1808581648b38bdc1ba1b105
PRIVATE_IMAGE_REFERENCE ?= docker.io/tosnetwork/software-work-go:1.26.5@$(PRIVATE_IMAGE_DIGEST)
# A root-only FIFO directory of the backend's own, apart from the service's.
PRIVATE_BACKEND_TEST_DIR ?= /run/tos-ai-backend-live

test-privileged:
	@sudo -n true || { echo "test-privileged needs passwordless sudo"; exit 1; }
	GOWORK=off go test -c -o bin/privileged/executorservice.test ./pkg/executorservice
	GOWORK=off go test -c -o bin/privileged/executord.test ./cmd/software-work-executord
	GOWORK=off go test -c -o bin/privileged/containerdbackend.test ./pkg/executor/containerdbackend
	sudo -n env TOS_AI_PRIVILEGED_TESTS=1 bin/privileged/executorservice.test \
		-test.run '^TestRealCallersAreAdmittedByTheirKernelUID$$' -test.count=1 -test.v
	sudo -n env TOS_AI_EXECUTORD_LIVE_CONTAINERD_SOCKET=$(PRIVATE_CONTAINERD_SOCKET) bin/privileged/executord.test \
		-test.run '^TestLiveServiceRunsARealJobForAnUnprivilegedCaller$$' -test.count=1 -test.v
	GOWORK=off go build -o bin/privileged/software-work-execute ./cmd/software-work-execute
	sudo -n env TOS_AI_EXECUTORD_LIVE_CONTAINERD_SOCKET=$(PRIVATE_CONTAINERD_SOCKET) \
		TOS_AI_EXECUTORD_UNIT_FILE=$(CURDIR)/deploy/provider/tos-service-executor.service \
		TOS_AI_EXECUTORD_GC_UNIT_FILE=$(CURDIR)/deploy/provider/tos-service-executor-gc.service \
		TOS_AI_EXECUTORD_GC_BINARY=$(CURDIR)/bin/privileged/software-work-execute \
		bin/privileged/executord.test \
		-test.run '^TestLiveServiceUnderTheShippedUnitSandbox$$' -test.count=1 -test.v
	sudo -n install -d -o root -g root -m 0700 $(PRIVATE_BACKEND_TEST_DIR)
	sudo -n env TOS_AI_CONTAINERD_TEST_SOCKET=$(PRIVATE_CONTAINERD_SOCKET) \
		TOS_AI_CONTAINERD_TEST_NAMESPACE=$(PRIVATE_CONTAINERD_NAMESPACE) \
		TOS_AI_CONTAINERD_TEST_FIFO_DIR=$(PRIVATE_BACKEND_TEST_DIR)/fifos \
		TOS_AI_CONTAINERD_TEST_IMAGE_REFERENCE=$(PRIVATE_IMAGE_REFERENCE) \
		TOS_AI_CONTAINERD_TEST_IMAGE_DIGEST=$(PRIVATE_IMAGE_DIGEST) \
		bin/privileged/containerdbackend.test \
		-test.run '^TestContainerdBackendLiveReadinessRequiresTheImage$$' -test.count=1 -test.v
