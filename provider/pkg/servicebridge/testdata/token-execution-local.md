# Frozen token execution read fixture

`token-execution-local.json.gz` retains fourteen public read responses and one
assembled task from a local token purchase at masterchain checkpoint 277040,
global id 3. The source transactions are independently reconstructed in the
operations repository's monitor-injection record. No signing key, vault value,
private custody configuration or unexecuted spending envelope is included.

The manifest and registry code are the actual compiled cells. The task contains
the public two-plus-two source archive, its Quote and the exact Call transaction
identity. RPC parameters and results are not rewritten. Node configuration paths
and endpoints are replaced by test-local files and HTTP servers. All clocks are
frozen to the captured chain time so the original deadline and monitor guards
are exercised without modifying transaction cells or bypassing verification.
The unused custody executable is the test binary; none of these tests signs.

The Registry v2 compatibility test opens the node against the original
responses and checks that typed state decoding refuses the historical Registry
v1 purchase evidence. The monitor wiring and provider retry tests use a
separate synthetic Registry v2 session. They exercise the same provider gate
installation, alarm and stale-report refusals, retry of an admitted slot without
a provider record, and single execution when a record exists.

Upstream comparison: this provider and its token-rail tests have no upstream
counterpart; inherited validator and VM code is unchanged.
