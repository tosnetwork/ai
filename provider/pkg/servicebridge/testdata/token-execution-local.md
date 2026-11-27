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

The node wiring test opens the real node, admits the task through its real gate,
then checks alarm and stale-report refusals without executing a callback. A clear
report is the positive control. Discarding the safety result must execute the
callback and fail the test. The provider retry test starts with an admitted slot
and no provider record: `HandleTask` must call the failing sentinel runner once,
retain its failure, and refuse a second execution. Inverting the retry branch
must fail that assertion.

Upstream comparison: this provider and its token-rail tests have no upstream
counterpart; inherited validator and VM code is unchanged.
