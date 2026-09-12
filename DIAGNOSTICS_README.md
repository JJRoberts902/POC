# PS5 Passive Diagnostics v13

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
