# Runtime image of the MCP buyer adapter's end-to-end harness
# (spec/docs/MCP_BUYER_ADAPTER_V1.md section 15). It holds no binary of its
# own: the tos build, the tos source, the uv Python and the binaries built
# by build.sh are mounted read-only, and only the run's work directory is
# writable.
#
# The base is pinned by digest. run.sh refuses to build when the local
# ubuntu:24.04 no longer resolves to it.
FROM ubuntu@sha256:73b999393d07f2bf65a40373778a44dc9a6d54ad7718d29247d8ff9413c4d6a8

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates openssl util-linux iproute2 \
        libssl3 libjemalloc2 libgsl27 libgslcblas0 libblas3 && \
    rm -rf /var/lib/apt/lists/*

# Fixed accounts: the buyer's custody account runs the agent and the
# confirmer, the developer account runs the MCP server, and the provider
# account runs OpenFox. Only developer is in the socket group, so only it
# reaches the agent socket besides custody. None can read another's home.
RUN groupadd --gid 2003 tos-buyer && \
    useradd --uid 2001 --user-group --create-home --shell /usr/sbin/nologin custody && \
    useradd --uid 2002 --user-group --groups tos-buyer --create-home --shell /usr/sbin/nologin developer && \
    useradd --uid 2004 --user-group --create-home --shell /usr/sbin/nologin provider && \
    useradd --uid 2005 --user-group --create-home --shell /usr/sbin/nologin stranger && \
    chmod 0700 /home/custody /home/developer /home/provider /home/stranger

# The harness starts as root only to give each account its directories, open
# the confirmer's pty with custody as its owner, and drop each process to
# its account; run.sh keeps only SETUID, SETGID, CHOWN and FOWNER and sets
# no-new-privileges. The tostester venv is mounted at /e2e-mounts/venv.
WORKDIR /e2e
ENTRYPOINT ["/e2e-mounts/venv/bin/python3", "-I", "/e2e-mounts/harness/run.py"]
