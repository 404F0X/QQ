# QQ research

Source research and reproducible models for QQ protocol and signature behavior. Signature work is incomplete; supported model behavior and remaining source gaps will be documented with the implementation.

The signature source model is accessed through `signature_core.py` from this checkout. It uses only registered, manifest-pinned source files and loads a fresh isolated namespace. Python 3.10 or newer is required. The focused model checks use the standard library; optional Windows/native integrations have their own requirements and are not exercised here.

```python
from signature_core import load_core

core = load_core()
try:
    with core.activate():
        from qq_nt_replica.primary_signer import PrimarySigner
        # Supply explicit model inputs for the supported source domain.
finally:
    core.close()
```

Run `python -B -m unittest discover -s tests -p test_isolation.py` from the checkout. The focused `check_static_unit.py` and `check_environment_values.py` scripts also require this checkout on `PYTHONPATH`; run them from a disposable output directory because they write check reports there.

See [signature state](docs/signature-state.md) for scope, missing assets and source identity conventions. Login integration is maintained separately.

The finite Own SDK OneBot caller defaults to offline inspection of an explicitly
recorded `get_login_info` reply:

```powershell
python -B run_own_sdk_onebot_candidate.py --metadata-json <recorded-reply.json> --expected-uin <own-uin>
```

Deferred real bindings exist in `own_sdk_onebot_bindings.py`. An actual run needs
separate execution authorization after review, including approval of the exact
owned storage and registry namespace. Implementation/model checks grant no such
authorization. Only an explicit `--run --live-config <private.json>` can open a
WebSocket or construct the Windows owner. Native/collector imports are deferred;
offline inspection neither creates storage nor reads SDK materials or registry.

The private JSON must explicitly provide `expected_uin`, `machine_id_hex` (your
own persistent, nonempty machine identity bytes, not a claimed Native identity),
absolute `bridge_path` and `worker_bridge_path`, a supported `loader_profile`,
`task_root`, unique ASCII `state_id`, `ws_url`, `overall_timeout`, `action_timeout`
and `receive_budget`. Timeouts must be positive finite seconds up to 120; the
receive budget must be 1–4096. Optional `token_file` supplies a private bearer
token. No token, account material, records or SDK values are provided by default.
Use the maintained manifest-pinned `signature_core` loader in this checkout;
historical capture scripts are not runtime dependencies. Windows/native bridge
and loader requirements still apply. The synchronous `websockets` 13.1 package
is needed only for an authorized real run; no automatic installation occurs.

`task_root` must be an existing, exclusively task-owned physical directory on G:,
outside all QQ stores. The run reserves a fresh `task_root/state_id`; signer
storage is its `sdk` child and collector files are
`collector/configuration.json` and `collector/Seconfig.dat`. The caller checks
the existing ancestor chain for reparse points and verifies final path resolution
before creation. The approved directory must remain under exclusive control
during execution. Registry persistence is restricted by the existing provider to
`HKCU\Software\404F0X\QQReplica\Signature\<state_id>` (`installFlag` REG_SZ and
`installStatus` value deletion). Before GO, approve this exact unique namespace
and its freshness; the class name alone proves no isolation. These OWN files and
keys may be retained for reproduction and can later be cleaned within that exact
owned scope. They must never alias QQ stores or QQ registry paths.

The transport uses public `websockets.sync.client.connect` with finite
`open_timeout`/`close_timeout` and `connection.recv(timeout=remaining)`. Message
waiting shares one monotonic overall/action deadline, including complete replies
with unrelated echoes; expiry is checked again before accepting a reply. The
installed library waits for a whole message: PING/PONG and nonfinal fragments do
not restart this message wait. It supplies its own daemon receiver thread; the
caller adds no receiver, watchdog or frame implementation. This is a **whole-message
waiting bound**, not an absolute wall-time bound on send, final receiver-thread
join or every OS call. The library's final join after socket shutdown has no
timeout. An authorized actual run therefore also needs a separate external process
wall budget and evidence of its own process exit. Mock checks establish use of
this public API; they do not prove real-library control/fragment behavior.

The caller checks identity before owner creation, then uses public initialization,
natural non-A2 request creation, one `send_pb`, and same-owner completion. Explicit
empty API body hex is forwarded as empty bytes to the decoder. API errors preserve
raw status/retcode/message and cancel the outstanding original; no API retcode is
treated as an SSO code. There is no reconnect, resend, AuthDTO, SID, fake sender or
flag override. `get_login_info` may refresh the Native nickname/profile and cause
its own protocol query; one public action does not imply one Native operation.

The current-thread profiler observes actual selection/digest calls and SIGN extra
without patching SDK functions. It reports `OBSERVED` only when a new nonempty
cache, actual selection, digest input/return, same-owner SIGN return/extra and
post-SIGN cache agree in order. Missing evidence remains `UNKNOWN`. The profiler
is restored before owner close; borrowed collector/port/mix/environment resources
close afterward. CAPI has no close API. Owner close failure retains its backing
and core activation on the exception; WS closure is independent. Cleanup errors
propagate. Persistence `io_errors` and registry False results remain visible,
without claiming all persistence succeeded or inventing a new success barrier.

Even a future positive result would establish only the observed Own SDK material
path through this opaque external carrier. It would not prove Own MSF login,
Native peer/header/signing provenance, use of the original Own SIGN, production
readiness or completion of every research goal. Offline tests use fake ports and
Python call identities; they do not exercise Native, sockets or registry.

