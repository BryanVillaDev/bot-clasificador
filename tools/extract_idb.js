/*
 * Transmit Security key/session extractor.
 *
 * HOW TO USE:
 *   1. Open the tab where checkclient.har was captured (or any page on
 *      apiauth.davivienda.com that has the Transmit SDK loaded).
 *   2. F12 -> Console.
 *   3. Paste this entire file and press Enter.
 *   4. It will print a JSON blob AND offer a download.
 *   5. Save it as: D:\Proyectos\BotCasa\capture\transmit_keys.json
 *
 * What it tries to extract:
 *   - All IndexedDB databases on the origin (Transmit SDK stores RSA keys there).
 *   - localStorage / sessionStorage entries matching ts-/transmit-/dxs- prefixes.
 *   - Attempts to export any CryptoKey it finds as JWK; reports extractable:false
 *     if the SDK created the key as non-extractable (which would block reuse).
 */
(async () => {
  const out = {
    origin: location.origin,
    capturedAt: new Date().toISOString(),
    databases: {},
    localStorage: {},
    sessionStorage: {},
    notes: [],
  };

  // ---- Storage scans -------------------------------------------------------
  const STORAGE_PREFIXES = /^(ts[-_:]|transmit|dxs|biocatch|mbass|tma|drs)/i;
  for (const [name, store] of [["localStorage", localStorage], ["sessionStorage", sessionStorage]]) {
    for (let i = 0; i < store.length; i++) {
      const k = store.key(i);
      if (!k) continue;
      if (STORAGE_PREFIXES.test(k)) {
        out[name][k] = store.getItem(k);
      }
    }
  }

  // ---- IndexedDB enumeration ----------------------------------------------
  let dbList;
  try {
    dbList = await indexedDB.databases();
  } catch (e) {
    out.notes.push("indexedDB.databases() unavailable: " + e.message);
    dbList = [];
  }

  for (const info of dbList) {
    const dbName = info.name;
    if (!dbName) continue;
    const dbDump = { version: info.version, stores: {} };
    try {
      const db = await new Promise((resolve, reject) => {
        const req = indexedDB.open(dbName);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      });
      for (const storeName of Array.from(db.objectStoreNames)) {
        const tx = db.transaction(storeName, "readonly");
        const store = tx.objectStore(storeName);
        const entries = await new Promise((resolve, reject) => {
          const all = [];
          const req = store.openCursor();
          req.onsuccess = (ev) => {
            const cur = ev.target.result;
            if (!cur) return resolve(all);
            all.push({ key: cur.key, value: cur.value });
            cur.continue();
          };
          req.onerror = () => reject(req.error);
        });

        // walk values and try to export any CryptoKey
        for (const entry of entries) {
          await walkAndExportKeys(entry, []);
        }
        dbDump.stores[storeName] = entries;
      }
      db.close();
    } catch (e) {
      dbDump.error = String(e.message || e);
    }
    out.databases[dbName] = dbDump;
  }

  // ---- Helpers -------------------------------------------------------------
  async function walkAndExportKeys(node, path) {
    if (!node || typeof node !== "object") return;
    if (node instanceof CryptoKey) {
      const tag = path.join(".") || "<root>";
      out.notes.push(`Found CryptoKey at ${tag}: type=${node.type} extractable=${node.extractable} usages=${node.usages.join(",")} alg=${JSON.stringify(node.algorithm)}`);
      if (node.extractable) {
        try {
          const jwk = await crypto.subtle.exportKey("jwk", node);
          node.__exportedJwk = jwk;
          out.notes.push(`  exported JWK kty=${jwk.kty} (${jwk.d ? "private" : "public"}) ok`);
        } catch (e) {
          out.notes.push(`  exportKey failed: ${e.message}`);
        }
      } else {
        out.notes.push(`  EXTRACTABLE=FALSE -- this key CANNOT be reused outside the browser.`);
      }
      return;
    }
    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i++) await walkAndExportKeys(node[i], path.concat(i));
      return;
    }
    for (const k of Object.keys(node)) {
      try {
        await walkAndExportKeys(node[k], path.concat(k));
      } catch (_) { /* ignore */ }
    }
  }

  // ---- Output --------------------------------------------------------------
  // CryptoKey objects don't serialize directly. Replace them with their exported JWK.
  const replacer = (k, v) => {
    if (v instanceof CryptoKey) {
      return { __CryptoKey: true, type: v.type, extractable: v.extractable, usages: v.usages, algorithm: v.algorithm, exportedJwk: v.__exportedJwk || null };
    }
    if (v instanceof ArrayBuffer) {
      return { __ArrayBuffer: true, b64: btoa(String.fromCharCode(...new Uint8Array(v))) };
    }
    if (ArrayBuffer.isView(v)) {
      return { __TypedArray: v.constructor.name, b64: btoa(String.fromCharCode(...new Uint8Array(v.buffer, v.byteOffset, v.byteLength))) };
    }
    return v;
  };
  const json = JSON.stringify(out, replacer, 2);

  // Make available globally
  window.__TS_DUMP__ = out;
  window.__TS_DUMP_JSON__ = json;

  // Download
  try {
    const blob = new Blob([json], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "transmit_keys.json";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    console.log("%c[transmit-extract] Downloaded transmit_keys.json. Save it to D:\\Proyectos\\BotCasa\\capture\\transmit_keys.json", "color: green; font-weight: bold");
  } catch (e) {
    console.log("Download failed, JSON below. Copy it manually:");
    console.log(json);
  }

  console.log("---- NOTES ----");
  out.notes.forEach((n) => console.log("  " + n));
  console.log("---- DBs found ----");
  console.log(Object.keys(out.databases));
  console.log("Full dump in window.__TS_DUMP__ and window.__TS_DUMP_JSON__");
})();
