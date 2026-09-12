"use strict";

(function () {
    const state = {
        generic: null,
        syscall: null,
        genericResult: null,
        syscallResult: null
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
        const ready = raw.pass === true
            && raw.smokeTestPassed === true
            && raw.returnedToUserland === true
            && raw.scope === "generic-userland";

        const result = {
            ready,
            registered: true,
            name: provider.name,
            firmware: provider.firmware,
            firmwareOK: true,
            smokeTestPassed: raw.smokeTestPassed === true,
            returnedToUserland: raw.returnedToUserland === true,
            scope: raw.scope || "unknown"
        };
        state.genericResult = result;

        mark(ctx, ready ? "GENERIC-NATIVE-CALL-READY" : "GENERIC-NATIVE-CALL-STATUS",
            `ready=${ready}-registered=true-name=${provider.name}`
            + `-scope=${result.scope}`
            + `-smoke=${result.smokeTestPassed}`
            + `-returned=${result.returnedToUserland}`);
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
        const ready = raw.pass === true
            && raw.smokeTestPassed === true
            && raw.returnedToUserland === true
            && raw.scope === "userland-syscall";

        const result = {
            ready,
            registered: true,
            name: provider.name,
            firmware: provider.firmware,
            firmwareOK: true,
            smokeTestPassed: raw.smokeTestPassed === true,
            returnedToUserland: raw.returnedToUserland === true,
            scope: raw.scope || "unknown"
        };
        state.syscallResult = result;

        mark(ctx, ready ? "SYSCALL-BRIDGE-READY" : "SYSCALL-BRIDGE-STATUS",
            `ready=${ready}-registered=true-name=${provider.name}`
            + `-scope=${result.scope}`
            + `-smoke=${result.smokeTestPassed}`
            + `-returned=${result.returnedToUserland}`);
        return result;
    }

    async function evaluate(ctx) {
        const generic = await evaluateGeneric(ctx || {});
        const syscall = await evaluateSyscall(ctx || {}, generic);
        return { generic, syscall };
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
            }
        };
    }

    window.PS5UserlandNativeProvider = {
        registerGeneric,
        registerSyscall,
        clearGeneric,
        clearSyscall,
        evaluate,
        evaluateGeneric,
        evaluateSyscall,
        getStatus
    };
})();
