// agent.js (compat + robust)
const OUTPUT_PATH = "%OUTPUT_FILE_PATH%" || "events.ndjson";
const CAND_LIBS = ["libcrypto.so.3", "libcrypto.so.1.1"];
const FUNCS_TO_HOOK = [
  "EVP_EncryptInit_ex2",
  "EVP_EncryptInit_ex",
  "EVP_CipherInit_ex",
  "EVP_CIPHER_CTX_set_key_length",
];

// ---- logging ----
let f; try { f = new File(OUTPUT_PATH, "a"); } catch { f = new File("/tmp/openssl_events.ndjson", "a"); }
const now = () => new Date().toISOString();
const write = (o) => { try { f.write(JSON.stringify(o) + "\n"); f.flush(); } catch (_) {} };
const info  = (o) => write(Object.assign({ ts: now(), event: "info" }, o));
const warn  = (msg) => write({ ts: now(), event: "warn", message: String(msg) });

// ---- export resolver (구/신 Frida 호환) ----
function resolveExport(name) {
  // 0) 전역 익스포트 우선
  try {
    const g = Module.findExportByName(null, name);
    if (g) return g;
  } catch (_) {}

  // 1) libcrypto.* 에서 찾기 (get/find 모두 대응)
  for (const lib of CAND_LIBS) {
    let m = null;
    try {
      if (typeof Process.findModuleByName === "function") {
        m = Process.findModuleByName(lib);      // 신버전
      } else if (typeof Process.getModuleByName === "function") {
        m = Process.getModuleByName(lib);       // 구버전 (없으면 throw)
      }
    } catch (_) { m = null; }

    if (!m) continue;
    try {
      const a = Module.findExportByName(m.name, name);
      if (a) return a;
    } catch (_) {}
  }

  // 2) ApiResolver('module') 와일드카드
  try {
    const resolver = new ApiResolver("module");
    const pats = [`exports:libcrypto*.so!*${name}`, `exports:*!${name}`];
    for (const p of pats) {
      try {
        const matches = resolver.enumerateMatchesSync(p);
        if (matches && matches.length) return matches[0].address;
      } catch (_) {}
    }
  } catch (_) {}

  // 3) DebugSymbol fallback (PLT/심볼만 있을 때)
  try {
    const dbg = DebugSymbol.fromName(name).address;
    if (dbg) return dbg;
  } catch (_) {}

  return null;
}

function nf(name, ret, args) {
  const a = resolveExport(name);
  return a ? new NativeFunction(a, ret, args) : null;
}

// ---- OpenSSL helper APIs ----
const EVP_CTX_get0_cipher =
  nf("EVP_CIPHER_CTX_get0_cipher", "pointer", ["pointer"]) ||
  nf("EVP_CIPHER_CTX_cipher",      "pointer", ["pointer"]);
const EVP_CIPHER_get_key_length = nf("EVP_CIPHER_get_key_length", "int", ["pointer"]);
const EVP_CIPHER_CTX_key_length = nf("EVP_CIPHER_CTX_key_length", "int", ["pointer"]);

function getKeyLenFromCtx(ctx) {
  let keyLen = -1;
  if (EVP_CIPHER_CTX_key_length) {
    try { keyLen = EVP_CIPHER_CTX_key_length(ctx); } catch (_) {}
  }
  if ((keyLen <= 0) && EVP_CTX_get0_cipher && EVP_CIPHER_get_key_length) {
    try {
      const c = EVP_CTX_get0_cipher(ctx);
      if (c && !c.isNull()) keyLen = EVP_CIPHER_get_key_length(c);
    } catch (_) {}
  }
  return keyLen;
}

// ---- attach helpers ----
function attachAll(name, handlerFactory) {
  let attached = 0;

  // A) 정확한 익스포트/주소
  const addr = resolveExport(name);
  if (addr) {
    try {
      Interceptor.attach(addr, handlerFactory(name));
      info({ event: "hook_attached", func: name, where: String(addr) });
      attached++;
    } catch (e) { warn(`attach ${name} failed: ${e.message}`); }
  }

  if (!attached) warn(`no address for ${name}`);
  return attached;
}

function makeInitHandler(funcName) {
  return {
    onEnter(args) {
      const ctx = args[0];
      if (!ctx || ctx.isNull()) return;

      const keyLen = getKeyLenFromCtx(ctx);
      let encFlag = null; // EVP_CipherInit_ex 전용
      if (funcName === "EVP_CipherInit_ex") {
        try { encFlag = args[5].toInt32(); } catch (_) {}
      }

      write({
        ts: now(),
        event: "keylen",
        func: funcName,
        pid: Process.id,
        tid: this.threadId,
        key_len_bytes: keyLen,
        enc_flag: encFlag
      });
    }
  };
}

function makeSetKeyLenHandler(funcName) {
  return {
    onEnter(args) {
      const requested = args[1] ? args[1].toInt32() : null;
      write({
        ts: now(),
        event: "set_keylen_call",
        func: funcName,
        pid: Process.id,
        tid: this.threadId,
        requested_len: requested
      });
    }
  };
}

// ---- main ----
(function () {
  info({
    event: "bindings",
    have_ctx_keylen: !!EVP_CIPHER_CTX_key_length,
    have_ctx_get0: !!EVP_CTX_get0_cipher,
    have_cipher_get_keylen: !!EVP_CIPHER_get_key_length
  });

  attachAll("EVP_EncryptInit_ex2",       makeInitHandler);
  attachAll("EVP_EncryptInit_ex",        makeInitHandler);
  attachAll("EVP_CipherInit_ex",         makeInitHandler);
  attachAll("EVP_CIPHER_CTX_set_key_length", makeSetKeyLenHandler);

  Interceptor.flush();
  write({ ts: now(), event: "agent_ready", pid: Process.id });
})();
