# PS5 Passive Diagnostics v14

This build adds passive runtime instrumentation only. It does not add a generic native caller, syscall bridge, pointer-marshalling primitive, kernel exploit primitive, or kernel R/W implementation.

## What is logged

- module/provider bindings and resource-load state
- service-worker controller state
- configured offsets and whether each came from defaults or URL overrides
- WebKit/libkernel base calculations and three import-equation cross-checks
- resolved notify/trampoline/arena/collator addresses and module-range checks
- existing proof/invariant state
- provider registration/readiness and the first unproven capability
- JS errors and unhandled promise rejections
- comparison with the previous run in the same session

Use **download diagnostics** to export `window.__PS5_DIAGNOSTICS` as JSON.

`native_bridge.js` and `kernel_prim.js` are included with `.disabled` suffix because the supplied copies are unfinished drafts and are not loaded by `exploit.html`.


## v14 native-boundary audit

This build adds passive logging around the already-working fixed notify-native call.
It records the original collator field, replacement fake-object pointer, stored notify
target, stored trampoline target, post-call restoration, return value, and a fixed-path
repeatability counter across reloads. It deliberately does **not** add generic target
selection, argument control, syscall dispatch, pointer marshalling, or kernel R/W.

Look for these records after a run:

- `DIAG-NATIVE-CALL-BOUNDARY`
- `DIAG-NATIVE-TARGET-AUDIT`
- `DIAG-NATIVE-ARGUMENT-MODEL`
- `DIAG-FIXED-NOTIFY-REPEATABILITY`
- `NATIVE-NEXT-BLOCKER`

`ripCaptured=false` is intentional: JavaScript cannot sample RIP during the synchronous
native call. The logger reports stored target provenance rather than claiming live CPU
register capture.
