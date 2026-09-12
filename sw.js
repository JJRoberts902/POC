--- /mnt/data/sw(2).js	2026-09-12 18:08:41.132770427 +0000
+++ /mnt/data/POC-native-interface-ready/sw.js	2026-09-12 18:12:32.338540536 +0000
@@ -1,7 +1,8 @@
-const V = "ps5poc-v5";
+const V = "ps5poc-v7";
 const SHELL = [
   "./", "./index.html", "./exploit.html",
   "./modules/offsets.mjs",
+  "./modules/krw_provider.js",
   "./modules/kernel_bagagwa.js",
   "./modules/exploit.js",
 ];
