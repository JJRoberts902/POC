# PS5 POC — v11 boundary-ready framework

This build keeps runtime proof honest while completing the provider/framework plumbing around the current userland stage.

## Proven runtime stages
- Userland primitive
- Native notify execution
- Native return/restoration
- Stage handoff
- Arena / notify proof

## Framework/API stages
The UI now separately reports framework readiness for:
- generic native provider API
- syscall provider API
- pointer diagnostic API
- kernel R/W provider API

These framework checks may pass even while the corresponding runtime capability remains unproven. They are intentionally separate.

## Runtime capability gates still require real proof
- Generic native call
- Syscall bridge
- Pointer marshalling
- Kernel exploit primitive
- Kernel R/W

No scratch provider or simulated K/RW pass is installed by this build.
