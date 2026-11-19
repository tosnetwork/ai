# Runtime image of the agent-operated Gate D pilot
# (spec/docs/GATE_D_EXTERNAL_PILOT.md section 8.5). It holds no binary of
# its own: build.sh's binaries, the harness and, for the local dress
# rehearsal, the tos build, the tos source and its Python are mounted
# read-only. The same image runs the buyer container and the verifier
# container; each uses only its own accounts.
#
# The base is pinned by digest. run-local.sh refuses to build when the
# local ubuntu:24.04 no longer resolves to it.
FROM ubuntu@sha256:73b999393d07f2bf65a40373778a44dc9a6d54ad7718d29247d8ff9413c4d6a8

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates openssl util-linux iproute2 openssh-client git \
        python3 libssl3 libjemalloc2 libgsl27 libgslcblas0 libblas3 && \
    rm -rf /var/lib/apt/lists/*

# The provider account must have the uid the host's executor service
# admits, and the executor socket's group, because the local dress
# rehearsal sends its jobs to that real service. The image's default
# ubuntu account would hold that uid, so it goes first.
ARG PROVIDER_UID=1000
ARG EXECUTOR_GID=997

# Accounts:
# - custody: the buyer agent, the confirmer, the buyer's tosctl vault and
#   SSH key;
# - developer: the MCP client (Claude Code) and the MCP server it starts;
#   the only member of the socket group besides custody;
# - provider: OpenFox, in the local dress rehearsal only;
# - verifier: the verifier container's Codex and tos-service-verify.
# None can read another's home.
RUN userdel --remove ubuntu 2>/dev/null || true; \
    groupadd --gid 2003 tos-buyer && \
    groupadd --gid "$EXECUTOR_GID" tos-executor && \
    useradd --uid 2001 --user-group --create-home --shell /usr/sbin/nologin custody && \
    useradd --uid 2002 --user-group --groups tos-buyer --create-home --shell /usr/sbin/nologin developer && \
    useradd --uid "$PROVIDER_UID" --user-group --groups tos-executor --create-home --shell /usr/sbin/nologin provider && \
    useradd --uid 2101 --user-group --create-home --shell /usr/sbin/nologin verifier && \
    chmod 0700 /home/custody /home/developer /home/provider /home/verifier

WORKDIR /pilot
