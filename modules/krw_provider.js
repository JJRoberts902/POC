"use strict";

(function () {
    const state = {
        active: null,
        lastResult: null
    };

    function mark(ctx, tag, extra) {
        if (ctx && typeof ctx.mark === "function") {
            ctx.mark(tag, extra);
            return;
        }

        try {
            console.log(tag, extra || "");
        } catch {}
    }

    function providerDescription(provider) {
        if (!provider) {
            return {
                registered: false,
                name: null,
                firmware: null,
                kind: null
            };
        }

        return {
            registered: true,
            name: provider.name || "unnamed",
            firmware: provider.firmware || "unknown",
            kind: provider.kind || "unknown"
        };
    }

    function validateProvider(provider) {
        if (!provider || typeof provider !== "object")
            throw new TypeError("krw-provider-invalid");

        if (typeof provider.name !== "string" || !provider.name.length)
            throw new TypeError("krw-provider-name-missing");

        if (typeof provider.firmware !== "string" || !provider.firmware.length)
            throw new TypeError("krw-provider-firmware-missing");

        if (typeof provider.selfTest !== "function")
            throw new TypeError("krw-provider-selftest-missing");

        return true;
    }

    function register(provider) {
        validateProvider(provider);

        state.active = provider;
        state.lastResult = null;

        return providerDescription(provider);
    }

    function clear() {
        state.active = null;
        state.lastResult = null;
    }

    function getProvider() {
        return state.active;
    }

    function firmwareMatches(provider, firmware) {
        return provider.firmware === "*"
            || provider.firmware === firmware;
    }

    async function selfTest(ctx) {
        const provider = state.active;

        if (!provider) {
            const result = {
                registered: false,
                pass: false,
                kernelVerified: false,
                reason: "provider-missing"
            };

            state.lastResult = result;

            mark(ctx,
                "KRW-PROVIDER-STATUS",
                "registered=false-pass=false");

            return result;
        }

        const firmware = ctx && ctx.firmware || "unknown";
        const firmwareOK = firmwareMatches(provider, firmware);

        if (!firmwareOK) {
            const result = {
                registered: true,
                name: provider.name,
                firmware: provider.firmware,
                firmwareOK: false,
                pass: false,
                kernelVerified: false,
                reason: "firmware-mismatch"
            };

            state.lastResult = result;

            mark(ctx,
                "KRW-PROVIDER-STATUS",
                `registered=true-name=${provider.name}`
                + `-provider-fw=${provider.firmware}`
                + `-runtime-fw=${firmware}`
                + "-fw-ok=false-pass=false");

            return result;
        }

        let raw;

        try {
            raw = await provider.selfTest({
                firmware,
                mark: (tag, extra) => mark(ctx, tag, extra)
            });
        } catch (error) {
            const result = {
                registered: true,
                name: provider.name,
                firmwareOK: true,
                pass: false,
                kernelVerified: false,
                reason: "selftest-threw",
                error: String(error && error.message || error)
            };

            state.lastResult = result;

            mark(ctx,
                "KRW-PROVIDER-SELFTEST-FAIL",
                String(error && error.message || error).slice(0, 96));

            return result;
        }

        raw = raw || {};

        const read = raw.read === true;
        const write = raw.write === true;
        const verify = raw.verify === true;

        /*
         * Important distinction:
         *
         * A scratch/mock provider can prove that the provider API works,
         * but it must NOT turn the real Kernel R/W card green.
         *
         * Only a provider identifying its verification scope as kernel
         * can produce kernelVerified=true.
         */
        const kernelVerified =
            raw.kernel === true &&
            raw.scope === "kernel";

        const pass = read && write && verify;

        const result = {
            registered: true,
            name: provider.name,
            firmware: provider.firmware,
            kind: provider.kind || "unknown",
            firmwareOK: true,
            read,
            write,
            verify,
            scope: raw.scope || "unknown",
            kernelVerified,
            pass
        };

        state.lastResult = result;

        mark(ctx,
            "KRW-PROVIDER-STATUS",
            `registered=true`
            + `-name=${provider.name}`
            + `-kind=${result.kind}`
            + `-fw-ok=true`);

        mark(ctx,
            "KRW-PROVIDER-SELFTEST",
            `read=${read}`
            + `-write=${write}`
            + `-verify=${verify}`
            + `-scope=${result.scope}`
            + `-kernel=${kernelVerified}`
            + `-pass=${pass}`);

        return result;
    }

    /*
     * Safe provider used only to prove the provider infrastructure works.
     * It operates exclusively on its own JavaScript ArrayBuffer.
     */
    function installScratchProvider() {
        const memory = new Uint8Array(0x100);

        register({
            name: "scratch-memory",
            firmware: "*",
            kind: "test",

            selfTest: function () {
                const offset = 0x40;
                const original = memory[offset];

                const read = memory[offset] === original;

                const testValue = original ^ 0x5a;

                memory[offset] = testValue;

                const write = memory[offset] === testValue;

                memory[offset] = original;

                const verify = memory[offset] === original;

                return {
                    read,
                    write,
                    verify,
                    scope: "scratch",
                    kernel: false
                };
            }
        });

        return state.active;
    }

    function getStatus() {
        return {
            provider: providerDescription(state.active),
            lastResult: state.lastResult
        };
    }

    window.PS5KRWProvider = {
        register,
        clear,
        getProvider,
        getStatus,
        selfTest,
        installScratchProvider
    };

    /*
     * Explicit test mode only.
     *
     * exploit.html?go=1&fw=13.60&krwtest=1
     */
    try {
        const q = new URLSearchParams(location.search);

        if (q.get("krwtest") === "1")
            installScratchProvider();
    } catch {}
})();
