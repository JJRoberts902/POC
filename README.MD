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
