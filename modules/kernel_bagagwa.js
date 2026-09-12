--- /mnt/data/kernel_bagagwa(1).js	2026-09-12 18:08:40.708769866 +0000
+++ /mnt/data/POC-native-interface-ready/modules/kernel_bagagwa.js	2026-09-12 18:12:32.381007132 +0000
@@ -300,6 +300,26 @@
         const userlandOK = !!(ctx && ctx.leakPass && ctx.notifyReady && ctx.gotReadOK);
         const firmwareOK = firmware === requiredFirmware;
         const handoffOK = firmwareOK && userlandOK && webkitOK && libkernelOK && arenaOK;
+        const nativeInterface = ctx && ctx.nativeInterface || null;
+        const nativeInterfaceReady = !!(nativeInterface
+            && nativeInterface.ready === true
+            && nativeInterface.smokeTestPassed === true
+            && nativeInterface.kind === "notify-native-call"
+            && nativeInterface.scope === "notify-only"
+            && nativeInterface.returnValue === 0
+            && nativeInterface.collatorRestored === true);
+
+        mark(ctx, "USERLAND-NATIVE-INTERFACE-STATUS",
+            `ready=${nativeInterfaceReady}`
+            + `-kind=${nativeInterface && nativeInterface.kind || "none"}`
+            + `-scope=${nativeInterface && nativeInterface.scope || "none"}`
+            + `-smoke=${!!(nativeInterface && nativeInterface.smokeTestPassed)}`
+            + `-generic-call=${!!(nativeInterface && nativeInterface.genericNativeCall)}`
+            + `-syscall=${!!(nativeInterface && nativeInterface.syscall)}`);
+
+        mark(ctx, handoffOK ? "KERNEL-HANDOFF-READY" : "KERNEL-HANDOFF-NOT-READY",
+            `pass=${handoffOK}`);
+
         const kernelRWOK = await evaluateKernelRWProof(ctx);
 
         const report = {
@@ -312,6 +332,7 @@
             gotReadOK: !!(ctx && ctx.gotReadOK),
             userlandOK,
             handoffOK,
+            nativeInterfaceReady,
             kernelRWOK,
             webkitOK,
             libcOK,
@@ -331,6 +352,7 @@
             + `-libkernel=${report.libkernelOK}`
             + `-arena=${report.arenaOK}`
             + `-handoff=${report.handoffOK}`
+            + `-native-interface=${report.nativeInterfaceReady}`
             + `-krw=${report.kernelRWOK}`);
 
         mark(ctx, "BAGAGWA-BASE-VALUES",
@@ -338,9 +360,13 @@
             + `-libc=${ctx && ctx.libcBase}`
             + `-libkernel=${ctx && ctx.libkernelBase}`);
 
-        mark(ctx, "BAGAGWA-PROBE-PASS",
-            `fw=${report.firmware}-handoff=${report.handoffOK}`
-            + "-handoff-only=true");
+        if (report.handoffOK) {
+            mark(ctx, "BAGAGWA-PROBE-PASS",
+                `fw=${report.firmware}-handoff=true-handoff-only=true`);
+        } else {
+            mark(ctx, "BAGAGWA-PROBE-FAIL",
+                `fw=${report.firmware}-handoff=false-handoff-only=true`);
+        }
         return report;
     }
 
