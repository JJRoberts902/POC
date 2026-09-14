/**
 * Generic Native Call Provider - PS5 13.60
 *
 * Wired into TWO systems:
 *  1. window.PS5GenericNativeProvider.evaluate(ctx)
 *     Called by exploit.js runGenericNativeStage() with ctx.callNative, ctx.getpidPointer, etc.
 *
 *  2. window.PS5UserlandNativeProvider.registerGeneric(provider)
 *     Called by the framework via provider.selfTest(ctx)
 *     Uses window.__PS5ExploitPrimitives.genericNativeCall
 */

"use strict";

(function () {

    // ====================================================================
    // SYSTEM 1: evaluate() — Called directly by exploit.js
    // exploit.js passes: callNative, stageAsciiArg, getpidPointer,
    //                    strlenPointer, notifyEntryAddress, mark
    // ====================================================================

    function evaluate(ctx) {
        const mark  = ctx.mark;
        const call  = ctx.callNative;
        const r = {
            getpidOK:          false,
            strlenOK:          false,
            notifyOK:          false,
            repeatOK:          false,
            distinct:          false,
            pass:              false,
            targetSelectable:  false,
            argumentsControlled: false,
            repeatable:        false
        };

        // 1. getpid — proves target is selectable (different from notify)
        try {
            const pid = call(ctx.getpidPointer);
            r.getpidOK = Number.isFinite(pid) && pid > 0 && pid < 99999;
            mark("GEN-TARGET-GETPID",
                `pid=${pid}-pass=${r.getpidOK}-addr=${hex(ctx.getpidPointer)}`);
        } catch (e) {
            mark("GEN-TARGET-GETPID-FAIL",
                `${e.name}:${String(e.message).slice(0, 80)}`);
        }

        // 2. strlen on a staged ASCII string — proves rdi argument control
        try {
            const argAddr = ctx.stageAsciiArg(
                [0x48, 0x41, 0x43, 0x4b, 0x45, 0x52, 0x00]); // "HACKER\0"
            const len = call(ctx.strlenPointer, argAddr);
            r.strlenOK = (len === 6);
            mark("GEN-TARGET-STRLEN",
                `len=${len}-expect=6-pass=${r.strlenOK}-arg=${hex(argAddr)}`);
        } catch (e) {
            mark("GEN-TARGET-STRLEN-FAIL",
                `${e.name}:${String(e.message).slice(0, 80)}`);
        }

        // 3. notify regression — same target still returns 0
        try {
            const nret = call(ctx.notifyEntryAddress);
            r.notifyOK = (nret === 0);
            mark("GEN-TARGET-NOTIFY",
                `ret=${nret}-pass=${r.notifyOK}`);
        } catch (e) {
            mark("GEN-TARGET-NOTIFY-FAIL",
                `${e.name}:${String(e.message).slice(0, 80)}`);
        }

        // 4. repeatability — getpid three more times
        try {
            let ok = true;
            for (let i = 0; i < 3; ++i) {
                const pid = call(ctx.getpidPointer);
                if (!Number.isFinite(pid) || pid <= 0 || pid >= 99999) {
                    ok = false; break;
                }
            }
            r.repeatOK = ok;
            mark("GEN-REPEAT", `pass=${ok}`);
        } catch (e) {
            mark("GEN-REPEAT-FAIL",
                `${e.name}:${String(e.message).slice(0, 80)}`);
        }

        // 5. distinctness — three callees are three different addresses
        r.distinct = new Set([
            ctx.getpidPointer,
            ctx.strlenPointer,
            ctx.notifyEntryAddress
        ]).size === 3;

        r.targetSelectable   = r.getpidOK && r.strlenOK && r.notifyOK && r.distinct;
        r.argumentsControlled = r.strlenOK;
        r.repeatable          = r.repeatOK && r.targetSelectable;
        r.pass                = r.targetSelectable && r.repeatable;

        mark("GENERIC-TARGET-SELECT",
            `getpid=${r.getpidOK}-strlen=${r.strlenOK}-notify=${r.notifyOK}`
            + `-repeat=${r.repeatOK}-distinct=${r.distinct}-pass=${r.pass}`);

        // Feed result into framework (System 2) if already registered
        if (r.pass && window._genericNativeProviderResolve) {
            window._genericNativeProviderResolve(r);
        }

        return r;
    }

    // ====================================================================
    // SYSTEM 2: selfTest() — Called by framework via registerGeneric()
    // Uses window.__PS5ExploitPrimitives.genericNativeCall (the real fn)
    // ====================================================================

    async function selfTest(ctx) {
        const firmware = (ctx && ctx.firmware) || "unknown";
        const mark     = (ctx && ctx.mark) || function () {};

        mark("GENERIC-SELFTEST-ENTER", `firmware=${firmware}`);

        // Wait up to 5s for exploit.js to export primitives
        const prim = await waitForPrimitives(5000);

        if (!prim) {
            mark("GENERIC-SELFTEST-FAIL", "reason=primitives-not-exported");
            return fail("primitives-not-exported");
        }

        const call          = prim.genericNativeCall;
        const stageAsciiArg = prim.stageAsciiArg;

        if (typeof call !== "function") {
            mark("GENERIC-SELFTEST-FAIL", "reason=genericNativeCall-not-a-function");
            return fail("genericNativeCall-not-a-function");
        }

        // Run the same tests as evaluate() using the exported call primitive
        const syntheticCtx = {
            mark,
            callNative:         call,
            stageAsciiArg:      stageAsciiArg,
            getpidPointer:      prim.getpidPointer,
            strlenPointer:      prim.strlenPointer,
            notifyEntryAddress: prim.notifyEntryAddress
        };

        let r;
        try {
            r = evaluate(syntheticCtx);
        } catch (e) {
            mark("GENERIC-SELFTEST-ERROR",
                `${e.name}:${String(e.message).slice(0, 80)}`);
            return fail("evaluate-threw");
        }

        mark("GENERIC-SELFTEST-RESULT",
            `getpid=${r.getpidOK}-strlen=${r.strlenOK}-notify=${r.notifyOK}`
            + `-repeat=${r.repeatOK}-distinct=${r.distinct}-pass=${r.pass}`);

        return {
            pass:               r.pass,
            smokeTestPassed:    r.getpidOK && r.notifyOK,
            returnedToUserland: true,
            scope:              "generic-userland",
            firmware,
            targetSelectable:   r.targetSelectable,
            argumentsControlled: r.argumentsControlled,
            repeatable:         r.repeatable
        };
    }

    // ====================================================================
    // Helpers
    // ====================================================================

    function fail(reason) {
        return {
            pass: false, smokeTestPassed: false,
            returnedToUserland: false,
            scope: "generic-userland",
            targetSelectable: false,
            argumentsControlled: false,
            repeatable: false,
            reason
        };
    }

    function hex(v) {
        if (v === null || v === undefined) return "null";
        if (typeof v === "bigint") return "0x" + v.toString(16);
        return "0x" + Math.floor(v).toString(16);
    }

    function waitForPrimitives(timeoutMs) {
        return new Promise(resolve => {
            // Already ready?
            const p = window.__PS5ExploitPrimitives;
            if (p && typeof p.genericNativeCall === "function") {
                return resolve(p);
            }
            // Poll
            const deadline = Date.now() + timeoutMs;
            const id = setInterval(() => {
                const p2 = window.__PS5ExploitPrimitives;
                if (p2 && typeof p2.genericNativeCall === "function") {
                    clearInterval(id);
                    resolve(p2);
                } else if (Date.now() > deadline) {
                    clearInterval(id);
                    resolve(null);
                }
            }, 100);
        });
    }

    // ====================================================================
    // Registration — both windows
    // ====================================================================

    const provider = {
        kind:     "generic",
        name:     "WebKit-Notify-Generic-Call-v3",
        firmware: "13.60",
        selfTest,
        evaluate  // keep evaluate for backward compat (exploit.js calls this)
    };

    // System 1: expose as PS5GenericNativeProvider (exploit.js looks here)
    window.PS5GenericNativeProvider = provider;

    // System 2: register with framework (native_provider.js)
    function tryRegister() {
        const layer = window.PS5UserlandNativeProvider;
        if (!layer || typeof layer.registerGeneric !== "function") return false;
        try {
            layer.registerGeneric(provider);
            return true;
        } catch (e) {
            return false;
        }
    }

    if (!tryRegister()) {
        let retries = 0;
        const iv = setInterval(() => {
            if (tryRegister() || retries++ > 50) clearInterval(iv);
        }, 100);
    }

    console.log("[GenericNativeProvider] v3 loaded — evaluate() + selfTest() both wired");

})();
