// agent.js — EVP init 계열에서 "키 길이"만 기록 (NDJSON)
// 1) 메인 모듈의 import(PLT/GOT)에서 바로 attach (가장 확실)
// 2) libcrypto.so.3 의 export 에도 attach 시도
// 3) 덤프: 메인 모듈 import 중 EVP_*Init* 이름 전부 기록 (디버깅)

const OUTPUT_PATH = "%OUTPUT_FILE_PATH%" || "events.ndjson";
const FUNCS = [
  "EVP_EncryptInit_ex",
  "EVP_EncryptInit",
  "EVP_EncryptInit_ex2",
  "EVP_CipherInit_ex",
  "EVP_CipherInit"
];

let f;
try { f = new File(OUTPUT_PATH, "a"); } catch { f = new File("/tmp/openssl_events.ndjson", "a"); }
const now = () => new Date().toISOString();
const write = (o) => { try { f.write(JSON.stringify(o) + "\n"); f.flush(); } catch (_) {} };
const info  = (obj) => { obj.ts = now(); obj.event = obj.event || "info"; write(obj); };
const warn  = (msg) => write({ ts: now(), event: "warn", message: msg });

function mainModule() {
  try {
    if (typeof Process.enumerateModulesSync === 'function') return Process.enumerateModulesSync()[0];
    if (typeof Process.enumerateModules === 'function') return Process.enumerateModules()[0];
  } catch {}
  return null;
}

function enumerateImports(mname) {
  try {
    if (typeof Module.enumerateImportsSync === 'function') return Module.enumerateImportsSync(mname);
  } catch {}
  const out = [];
  try {
    if (typeof Module.enumerateImports === 'function') {
      Module.enumerateImports(mname, { onMatch: (m) => out.push(m), onComplete: () => {} });
    }
  } catch {}
  return out;
}

// ---------- OpenSSL helper 심볼 (동적) ----------
let _klen = null, _getCipher = null;
function bindKeyLen() {
  if (_klen) return _klen;
  try {
    const a = Module.findExportByName("libcrypto.so.3", "EVP_CIPHER_key_length") ||
              Module.findExportByName(null, "EVP_CIPHER_key_length");
    if (!a) return null;
    _klen = new NativeFunction(a, "int", ["pointer"]);
  } catch (e) { warn("bind EVP_CIPHER_key_length: " + e.message); }
  return _klen;
}
function bindGetCipher() {
  if (_getCipher) return _getCipher;
  try {
    const a = Module.findExportByName("libcrypto.so.3", "EVP_CIPHER_CTX_get0_cipher") ||
              Module.findExportByName(null, "EVP_CIPHER_CTX_get0_cipher");
    if (!a) return null;
    _getCipher = new NativeFunction(a, "pointer", ["pointer"]);
  } catch (e) { warn("bind EVP_CIPHER_CTX_get0_cipher: " + e.message); }
  return _getCipher;
}

function attachCommon(addr, name) {
  if (!addr) return false;
  Interceptor.attach(addr, {
    onEnter(args) {
      const ctx = args[0];
      let cipher = args[1] || ptr(0);

      const getC = bindGetCipher();
      if ((cipher.isNull && cipher.isNull()) && getC) {
        try { cipher = getC(ctx); } catch {}
      }

      let keyLen = -1;
      const kf = bindKeyLen();
      if (cipher && (!cipher.isNull || cipher.toString() !== "0x0") && kf) {
        try { keyLen = kf(cipher); } catch { keyLen = -1; }
      }

      write({ ts: now(), event: "keylen", func: name, pid: Process.id, tid: Thread.id, key_len: keyLen });
    }
  });
  info({ event: "hook_attached", where: String(addr), func: name });
  return true;
}

// 1) 메인 모듈 import(PLT/GOT)에서 훅
(function attachImports() {
  const mod = mainModule();
  if (!mod) { warn("main module not found"); return; }

  const imps = enumerateImports(mod.name) || [];
  // 디버깅: EVP_*Init* import 전부 덤프
  imps.forEach(imp => {
    if (imp && imp.name && /EVP_.*Init/.test(imp.name)) {
      info({ event: "import_dbg", name: imp.name, module: imp.module || "", addr: imp.address ? String(ptr(imp.address)) : "" });
    }
  });

  let attachedCount = 0;
  for (const want of FUNCS) {
    const hit = imps.find(imp => imp && imp.name && imp.name.indexOf(want) !== -1 && imp.address);
    if (hit && attachCommon(ptr(hit.address), want)) attachedCount++;
  }
  info({ event: "import_attach_summary", attached: attachedCount });
})();

// 2) libcrypto export에서도 훅 (백업)
(function attachExports() {
  for (const want of FUNCS) {
    try {
      const a = Module.findExportByName("libcrypto.so.3", want) ||
                Module.findExportByName(null, want);
      if (a) attachCommon(a, want);
    } catch {}
  }
})();

// 완료
write({ ts: now(), event: "agent_ready", pid: Process.id, target_funcs: FUNCS });
