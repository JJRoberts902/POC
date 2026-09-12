"use strict";

(function () {
    const state = {
        generic: null,
        syscall: null,
        genericResult: null,
        syscallResult: null,
        pointerProbe: null,
        pointerResult: null
    };

    function mark(ctx, tag, extra) {
        if (ctx && typeof ctx.mark === "function") {
            ctx.mark(tag, extra);
            return;
        }
        try { console.log(tag, extra || ""); } catch {}
    }

    function firmwareMatches(provider, firmware) {
        return provider && (provider.firmware === "*" || provider.firmware === firmware);
    }

    function validateProvider(provider, kind) {
        if (!provider || typeof provider !== "object")
            throw new TypeError(`${kind}-provider-invalid`);
        if (typeof provider.name !== "string" || !provider.name.length)
            throw new TypeError(`${kind}-provider-name-missing`);
        if (typeof provider.firmware !== "string" || !provider.firmware.length)
            throw new TypeError(`${kind}-provider-firmware-missing`);
        if (typeof provider.selfTest !== "function")
            throw new TypeError(`${kind}-provider-selftest-missing`);
        return true;
    }

    function registerGeneric(provider) {
        validateProvider(provider, "generic-native");
        state.generic = provider;
        state.genericResult = null;
        return { registered: true, name: provider.name, firmware: provider.firmware };
    }

    function registerSyscall(provider) {
        validateProvider(provider, "syscall");
        state.syscall = provider;
        state.syscallResult = null;
        return { registered: true, name: provider.name, firmware: provider.firmware };
    }

    function clearGeneric() {
        state.generic = null;
        state.genericResult = null;
    }

    function clearSyscall() {
        state.syscall = null;
        state.syscallResult = null;
    }

    async function evaluateGeneric(ctx) {
        const provider = state.generic;
        if (!provider) {
            const result = {
                ready: false,
                registered: false,
                reason: "provider-missing"
            };
            state.genericResult = result;
            mark(ctx, "GENERIC-NATIVE-CALL-STATUS",
                "ready=false-registered=false-reason=provider-missing");
            return result;
        }

        const firmware = ctx && ctx.firmware || "unknown";
        if (!firmwareMatches(provider, firmware)) {
            const result = {
                ready: false,
                registered: true,
                name: provider.name,
                firmwareOK: false,
                reason: "firmware-mismatch"
            };
            state.genericResult = result;
            mark(ctx, "GENERIC-NATIVE-CALL-STATUS",
                `ready=false-registered=true-name=${provider.name}`
                + `-provider-fw=${provider.firmware}-runtime-fw=${firmware}`
                + "-reason=firmware-mismatch");
            return result;
        }

        let raw;
        try {
            raw = await provider.selfTest({
                firmware,
                notifyInterface: ctx && ctx.notifyInterface || null,
                mark: (tag, extra) => mark(ctx, tag, extra)
            });
        } catch (error) {
            const result = {
                ready: false,
                registered: true,
                name: provider.name,
                firmwareOK: true,
                reason: "selftest-threw",
                error: String(error && error.message || error)
            };
            state.genericResult = result;
            mark(ctx, "GENERIC-NATIVE-CALL-STATUS",
                `ready=false-registered=true-name=${provider.name}`
                + "-reason=selftest-threw");
            return result;
        }

        raw = raw || {};
        const targetSelectable = raw.targetSelectable === true;
        const argumentsControlled = raw.argumentsControlled === true;
        const repeatable = raw.repeatable === true;
        const ready = raw.pass === true
            && raw.smokeTestPassed === true
            && raw.returnedToUserland === true
            && raw.scope === "generic-userland"
            && targetSelectable
            && argumentsControlled
            && repeatable;

        const result = {
            ready,
            registered: true,
            name: provider.name,
            firmware: provider.firmware,
            firmwareOK: true,
            smokeTestPassed: raw.smokeTestPassed === true,
            returnedToUserland: raw.returnedToUserland === true,
            targetSelectable,
            argumentsControlled,
            repeatable,
            scope: raw.scope || "unknown",
            reason: ready ? null
                : !targetSelectable ? "target-selection-not-proven"
                : !argumentsControlled ? "argument-control-not-proven"
                : !repeatable ? "repeatability-not-proven"
                : "generic-native-selftest-not-passed"
        };
        state.genericResult = result;

        mark(ctx, ready ? "GENERIC-NATIVE-CALL-READY" : "GENERIC-NATIVE-CALL-STATUS",
            `ready=${ready}-registered=true-name=${provider.name}`
            + `-scope=${result.scope}`
            + `-smoke=${result.smokeTestPassed}`
            + `-returned=${result.returnedToUserland}`
            + `-target-selectable=${result.targetSelectable}`
            + `-args-controlled=${result.argumentsControlled}`
            + `-repeatable=${result.repeatable}`
            + (result.reason ? `-reason=${result.reason}` : ""));
        return result;
    }

    async function evaluateSyscall(ctx, genericResult) {
        if (!genericResult || genericResult.ready !== true) {
            const result = {
                ready: false,
                registered: !!state.syscall,
                reason: "generic-native-not-ready"
            };
            state.syscallResult = result;
            mark(ctx, "SYSCALL-BRIDGE-STATUS",
                `ready=false-registered=${!!state.syscall}`
                + "-reason=generic-native-not-ready");
            return result;
        }

        const provider = state.syscall;
        if (!provider) {
            const result = {
                ready: false,
                registered: false,
                reason: "provider-missing"
            };
            state.syscallResult = result;
            mark(ctx, "SYSCALL-BRIDGE-STATUS",
                "ready=false-registered=false-reason=provider-missing");
            return result;
        }

        const firmware = ctx && ctx.firmware || "unknown";
        if (!firmwareMatches(provider, firmware)) {
            const result = {
                ready: false,
                registered: true,
                name: provider.name,
                firmwareOK: false,
                reason: "firmware-mismatch"
            };
            state.syscallResult = result;
            mark(ctx, "SYSCALL-BRIDGE-STATUS",
                `ready=false-registered=true-name=${provider.name}`
                + `-provider-fw=${provider.firmware}-runtime-fw=${firmware}`
                + "-reason=firmware-mismatch");
            return result;
        }

        let raw;
        try {
            raw = await provider.selfTest({
                firmware,
                genericProvider: state.generic,
                mark: (tag, extra) => mark(ctx, tag, extra)
            });
        } catch (error) {
            const result = {
                ready: false,
                registered: true,
                name: provider.name,
                firmwareOK: true,
                reason: "selftest-threw",
                error: String(error && error.message || error)
            };
            state.syscallResult = result;
            mark(ctx, "SYSCALL-BRIDGE-STATUS",
                `ready=false-registered=true-name=${provider.name}`
                + "-reason=selftest-threw");
            return result;
        }

        raw = raw || {};
        const dispatchVerified = raw.dispatchVerified === true;
        const scalarArgsVerified = raw.scalarArgsVerified === true;
        const repeatable = raw.repeatable === true;
        const pointerMarshalling = raw.pointerMarshalling === true;
        const ready = raw.pass === true
            && raw.smokeTestPassed === true
            && raw.returnedToUserland === true
            && raw.scope === "userland-syscall"
            && dispatchVerified
            && scalarArgsVerified
            && repeatable;

        const result = {
            ready,
            registered: true,
            name: provider.name,
            firmware: provider.firmware,
            firmwareOK: true,
            smokeTestPassed: raw.smokeTestPassed === true,
            returnedToUserland: raw.returnedToUserland === true,
            dispatchVerified,
            scalarArgsVerified,
            repeatable,
            pointerMarshalling,
            scope: raw.scope || "unknown",
            reason: ready ? null
                : !dispatchVerified ? "syscall-dispatch-not-proven"
                : !scalarArgsVerified ? "syscall-scalar-args-not-proven"
                : !repeatable ? "syscall-repeatability-not-proven"
                : "syscall-selftest-not-passed"
        };
        state.syscallResult = result;

        mark(ctx, ready ? "SYSCALL-BRIDGE-READY" : "SYSCALL-BRIDGE-STATUS",
            `ready=${ready}-registered=true-name=${provider.name}`
            + `-scope=${result.scope}`
            + `-smoke=${result.smokeTestPassed}`
            + `-returned=${result.returnedToUserland}`
            + `-dispatch=${result.dispatchVerified}`
            + `-scalar-args=${result.scalarArgsVerified}`
            + `-repeatable=${result.repeatable}`
            + `-pointer-marshalling=${result.pointerMarshalling}`
            + (result.reason ? `-reason=${result.reason}` : ""));
        return result;
    }


    function registerPointerProbe(provider) {
        validateProvider(provider, "pointer-diagnostic");
        state.pointerProbe = provider;
        state.pointerResult = null;
        return { registered: true, name: provider.name, firmware: provider.firmware };
    }

    function clearPointerProbe() {
        state.pointerProbe = null;
        state.pointerResult = null;
    }

    async function evaluatePointerProbe(ctx, syscallResult) {
        if (!syscallResult || syscallResult.ready !== true) {
            const result = { ready: false, registered: !!state.pointerProbe, reason: "syscall-bridge-not-ready" };
            state.pointerResult = result;
            mark(ctx, "POINTER-MARSHALLING-STATUS",
                `ready=false-registered=${!!state.pointerProbe}-reason=syscall-bridge-not-ready`);
            return result;
        }

        const provider = state.pointerProbe;
        if (!provider) {
            const result = { ready: false, registered: false, reason: "provider-missing" };
            state.pointerResult = result;
            mark(ctx, "POINTER-MARSHALLING-STATUS",
                "ready=false-registered=false-reason=provider-missing");
            return result;
        }

        const firmware = ctx && ctx.firmware || "unknown";
        if (!firmwareMatches(provider, firmware)) {
            const result = { ready: false, registered: true, name: provider.name, reason: "firmware-mismatch" };
            state.pointerResult = result;
            mark(ctx, "POINTER-MARSHALLING-STATUS",
                `ready=false-registered=true-name=${provider.name}-reason=firmware-mismatch`);
            return result;
        }

        let raw;
        try {
            raw = await provider.selfTest({ firmware, mark: (tag, extra) => mark(ctx, tag, extra) });
        } catch (error) {
            const result = { ready: false, registered: true, name: provider.name, reason: "selftest-threw" };
            state.pointerResult = result;
            mark(ctx, "POINTER-MARSHALLING-STATUS",
                `ready=false-registered=true-name=${provider.name}-reason=selftest-threw`);
            return result;
        }

        raw = raw || {};
        const ready = raw.pass === true
            && raw.scope === "userland-pointer-diagnostic"
            && raw.addressObserved === true
            && raw.roundTripVerified === true
            && raw.returnedToUserland === true;
        const result = {
            ready,
            registered: true,
            name: provider.name,
            addressObserved: raw.addressObserved === true,
            roundTripVerified: raw.roundTripVerified === true,
            returnedToUserland: raw.returnedToUserland === true,
            scope: raw.scope || "unknown",
            reason: ready ? null : "pointer-marshalling-not-proven"
        };
        state.pointerResult = result;
        mark(ctx, ready ? "POINTER-MARSHALLING-READY" : "POINTER-MARSHALLING-STATUS",
            `ready=${ready}-registered=true-name=${provider.name}`
            + `-address-observed=${result.addressObserved}`
            + `-roundtrip=${result.roundTripVerified}`
            + `-returned=${result.returnedToUserland}`
            + (result.reason ? `-reason=${result.reason}` : ""));
        return result;
    }

    function getFrameworkStatus() {
        return {
            genericApi: typeof registerGeneric === "function" && typeof evaluateGeneric === "function",
            syscallApi: typeof registerSyscall === "function" && typeof evaluateSyscall === "function",
            pointerApi: typeof registerPointerProbe === "function" && typeof evaluatePointerProbe === "function"
        };
    }

    async function evaluate(ctx) {
        const generic = await evaluateGeneric(ctx || {});
        const syscall = await evaluateSyscall(ctx || {}, generic);
        const pointer = await evaluatePointerProbe(ctx || {}, syscall);
        return { generic, syscall, pointer };
    }

    function getStatus() {
        return {
            generic: {
                registered: !!state.generic,
                name: state.generic && state.generic.name || null,
                result: state.genericResult
            },
            syscall: {
                registered: !!state.syscall,
                name: state.syscall && state.syscall.name || null,
                result: state.syscallResult
            },
            pointer: {
                registered: !!state.pointerProbe,
                name: state.pointerProbe && state.pointerProbe.name || null,
                result: state.pointerResult
            },
            framework: getFrameworkStatus()
        };
    }

    window.PS5UserlandNativeProvider = {
        registerGeneric,
        registerSyscall,
        registerPointerProbe,
        clearGeneric,
        clearSyscall,
        clearPointerProbe,
        evaluate,
        evaluateGeneric,
        evaluateSyscall,
        evaluatePointerProbe,
        getFrameworkStatus,
        getStatus
    };
})();
