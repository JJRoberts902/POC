Stages :
Userland: PASS
Notify/native call: PASS
Userland native interface ready: PASS
Generic native call: REQUIRES INDIVIDUAL CAPABILITY PROOFS
Syscall bridge: BLOCKED UNTIL GENERIC NATIVE CALL IS READY
Second-stage module loaded: PASS
Kernel R/W: NOT RUNNING
Kernel payload: NOT RUNNING

Notes:
- No scratch/mock native provider is installed.
- v10 fixes diagnostic ordering. Provider registration is no longer reported as the first blocker when target selection, argument control, or repeatability have not been proven.
- The current proven path is identified as target-model=fixed-notify and argument-model=fixed-notify-layout.
- A real generic provider must explicitly prove targetSelectable, argumentsControlled, and repeatable before GENERIC-NATIVE-CALL-READY can pass.
- A real syscall provider must explicitly prove dispatchVerified, scalarArgsVerified, and repeatable before SYSCALL-BRIDGE-READY can pass.
- Pointer marshalling is tracked separately after a syscall bridge is ready.
- Kernel R/W remains false until a genuine kernel-backed provider is verified.

## v10 ordered diagnostics

After NOTIFY-NATIVE-CALL-PASS, look for:
- NATIVE-CAPABILITY-DIAG
- NATIVE-PROOF-MATRIX
- NATIVE-NEXT-BLOCKER
- GENERIC-NATIVE-REQUIREMENTS

With the current notify-only implementation and no real generic provider, the expected first blocker is target-selection-not-proven.
