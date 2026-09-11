"use strict";

// Kernel research stage interface.
//
// This module consumes the already-proven userland context and reports research
// readiness/proof state. It does not auto-run or perform destructive actions.
(function () {
    const STAGE_NAME = "bagagwa-aio-research";

    function asHex(value) {
        if (!Number.isFinite(value))
            return "nan";
        return "0x" + Math.floor(value).toString(16);
    }

    function mark(ctx, tag, extra) {
        if (ctx && typeof ctx.mark === "function") {
            ctx.mark(tag, extra);
            return;
        }
        try {
            console.log(tag, extra || "");
        } catch {}
    }

    function hasNumber(ctx, key) {
        return Number.isFinite(ctx && ctx[key]) && ctx[key] > 0;
    }

    function buildReport(ctx) {
        const report = {
            stage: STAGE_NAME,
            firmware: ctx.firmware || "unknown",
            userlandReady: !!ctx.leakPass,
            nativeCallReady: !!ctx.notifyReady,
            readPrimitiveReady: !!ctx.gotReadOK,
            webkitBaseReady: hasNumber(ctx, "webkitBase"),
            libcBaseReady: hasNumber(ctx, "libcBase"),
            libkernelBaseReady: hasNumber(ctx, "libkernelBase"),
            realKernelBaseKnown: false,
            syscallBridgeReady: false,
            aioUafValidated: false,
            aioDebugLeakValidated: false,
            decrementPrimitiveValidated: false,
            osemCandidateValidated: false
        };

        report.readyForKernelResearch =
            report.userlandReady
            && report.nativeCallReady
            && report.readPrimitiveReady
            && report.webkitBaseReady
            && report.libcBaseReady
            && report.libkernelBaseReady;

        return report;
    }

    async function analyze(ctx) {
        const report = buildReport(ctx || {});

        mark(ctx, "KERNEL-STAGE-BEGIN",
            `name=${report.stage}-fw=${report.firmware}`);
        mark(ctx, "KERNEL-CONTEXT",
            `webkit=${asHex(ctx.webkitBase)}`
            + `-libc=${asHex(ctx.libcBase)}`
            + `-libkernel=${asHex(ctx.libkernelBase)}`
            + `-notify=${asHex(ctx.notifyEntryAddress)}`);

        if (!report.readyForKernelResearch) {
            mark(ctx, "KERNEL-STAGE-BLOCKED",
                `userland=${report.userlandReady}`
                + `-native=${report.nativeCallReady}`
                + `-read=${report.readPrimitiveReady}`
                + `-webkit=${report.webkitBaseReady}`
                + `-libc=${report.libcBaseReady}`
                + `-libkernel=${report.libkernelBaseReady}`);
            return report;
        }

        mark(ctx, "KERNEL-STAGE-PASS",
            "userland-context-ready=true-real-kernel-base=false");
        mark(ctx, "KERNEL-RESEARCH-GAPS",
            "syscall-bridge=false-aio-uaf=false-sys727-leak=false"
            + "-decrement=false-osem=false");
        mark(ctx, "KERNEL-STAGE-END",
            "instrumentation-only=true-no-kernel-payload-run=true");

        return report;
    }

    window.PS5KernelResearch = {
        analyze,
        buildReport
    };
})();
