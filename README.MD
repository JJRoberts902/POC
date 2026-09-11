# PS5 Research Framework

Educational security research platform for analyzing PS5 system architecture.

## Purpose

This repository provides a structural framework for:
- Understanding WebKit/JavaScript engine internals
- Analyzing kernel syscall interfaces
- Educational exploration of system security concepts

## Structure

- `index.html` - Entry point and firmware selection
- `exploit.html` - Research session interface
- `modules/framework.js` - Core research framework
- `modules/exploit.js` - Userland analysis module
- `modules/kernel_bagagwa.js` - Kernel research stage interface, called after userland context validation

## Usage

1. Serve files via local web server
2. Open in compatible browser environment
3. Select target firmware version
4. Review documentation and analysis output

## Research Areas

### Userland
- JavaScript engine heap analysis
- Memory primitive development
- Module base identification

### Kernel
- Syscall interface analysis
- Memory management study
- Security primitive documentation

## Runtime Flow

`exploit.html` loads `modules/kernel_bagagwa.js` before `modules/exploit.js`.
When the userland stage validates its read primitive, module bases, and native
notification context, `modules/exploit.js` builds a research context and calls
`window.PS5KernelResearch.analyze(ctx)`. Kernel Handoff Test Run 2 starts as
soon as `MODULE-IMPORT-LEAK-PASS` is reached, before the final notification
commit gate. It reports whether the handoff ran, whether a syscall bridge is
present, and the state of the notify gate booleans. It records that syscall 727
and the AIO path were not attempted, marks the exploit as not attempted, and
then leaves the existing notification proof untouched.

## Disclaimer

For authorized security research only. Use only on systems you own and have 
permission to test. This framework is for educational purposes and does 
not contain functional exploit code.

## References

Based on publicly disclosed security research and documentation.
