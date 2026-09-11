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
- `modules/kernel_bagagwa.js` - Kernel research interface

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

## Disclaimer

For authorized security research only. Use only on systems you own and have 
permission to test. This framework is for educational purposes and does 
not contain functional exploit code.

## References

Based on publicly disclosed security research and documentation.