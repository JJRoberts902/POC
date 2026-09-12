Stages :
Userland: PASS
Notify/native call: PASS
Userland native interface ready: PASS
Generic native call: PROVIDER REQUIRED
Syscall bridge: PROVIDER REQUIRED
Second-stage module loaded: PASS
Kernel R/W: NOT RUNNING
Kernel payload: NOT RUNNING

Notes:
- No scratch/mock native provider is installed.
- Generic native call only passes after a registered real provider passes its own userland smoke test and returns to userland.
- Syscall bridge only passes after generic native call is ready and a registered real syscall provider passes its own smoke test.
- Kernel R/W remains false until a kernel-backed provider is genuinely verified.

## v9 native readiness diagnostics

This revision keeps exploit behavior unchanged and adds passive diagnostic logging for the userland-native progression. After the real notify-native proof, logs now report `NATIVE-CAPABILITY-DIAG`, `NATIVE-NEXT-BLOCKER`, and requirement summaries. Unproven capabilities remain explicitly `not-proven`; no provider or K/RW status is simulated.
