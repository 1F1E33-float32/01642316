mod resource;

use std::ffi::{CStr, CString, c_char, c_void};
use std::fs::{OpenOptions, remove_file};
use std::io::Write;
use std::mem::transmute;
use std::ptr::{copy_nonoverlapping, null, null_mut};
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::{HMODULE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Console::{AllocConsole, GetStdHandle, STD_OUTPUT_HANDLE, SetConsoleTitleA, WriteConsoleA};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

type NapiEnv = *mut c_void;
type NapiValue = *mut c_void;
type NapiCallbackInfo = *mut c_void;
type NapiStatus = i32;

const NAPI_OK: NapiStatus = 0;
const NAPI_AUTO_LENGTH: usize = usize::MAX;

type NapiCreateStringUtf8 = unsafe extern "C" fn(NapiEnv, *const c_char, usize, *mut NapiValue) -> NapiStatus;
type NapiRunScript = unsafe extern "C" fn(NapiEnv, NapiValue, *mut NapiValue) -> NapiStatus;
type NapiGetNamedProperty = unsafe extern "C" fn(NapiEnv, NapiValue, *const c_char, *mut NapiValue) -> NapiStatus;
type NapiSetNamedProperty = unsafe extern "C" fn(NapiEnv, NapiValue, *const c_char, NapiValue) -> NapiStatus;
type NapiGetGlobal = unsafe extern "C" fn(NapiEnv, *mut NapiValue) -> NapiStatus;
type NapiCreateFunction = unsafe extern "C" fn(NapiEnv, *const c_char, usize, NapiCallback, *mut c_void, *mut NapiValue) -> NapiStatus;
type NapiCallback = unsafe extern "C" fn(NapiEnv, NapiCallbackInfo) -> NapiValue;
type NapiGetCbInfo = unsafe extern "C" fn(NapiEnv, NapiCallbackInfo, *mut usize, *mut NapiValue, *mut NapiValue, *mut *mut c_void) -> NapiStatus;
type NapiGetValueStringUtf8 = unsafe extern "C" fn(NapiEnv, NapiValue, *mut c_char, usize, *mut usize) -> NapiStatus;
type NapiCreateArraybuffer = unsafe extern "C" fn(NapiEnv, usize, *mut *mut c_void, *mut NapiValue) -> NapiStatus;
type NapiGetNull = unsafe extern "C" fn(NapiEnv, *mut NapiValue) -> NapiStatus;
type NapiCreateInt32 = unsafe extern "C" fn(NapiEnv, i32, *mut NapiValue) -> NapiStatus;
type NapiCallFunction = unsafe extern "C" fn(NapiEnv, NapiValue, NapiValue, usize, *const NapiValue, *mut NapiValue) -> NapiStatus;
type NapiThrowError = unsafe extern "C" fn(NapiEnv, *const c_char, *const c_char) -> NapiStatus;
type NapiGetBoolean = unsafe extern "C" fn(NapiEnv, bool, *mut NapiValue) -> NapiStatus;
type NapiCreateObject = unsafe extern "C" fn(NapiEnv, *mut NapiValue) -> NapiStatus;

struct Napi {
    create_string_utf8: NapiCreateStringUtf8,
    run_script: NapiRunScript,
    get_named_property: NapiGetNamedProperty,
    set_named_property: NapiSetNamedProperty,
    get_global: NapiGetGlobal,
    create_function: NapiCreateFunction,
    get_cb_info: NapiGetCbInfo,
    get_value_string_utf8: NapiGetValueStringUtf8,
    create_arraybuffer: NapiCreateArraybuffer,
    get_null: NapiGetNull,
    create_int32: NapiCreateInt32,
    call_function: NapiCallFunction,
    throw_error: NapiThrowError,
    get_boolean: NapiGetBoolean,
    create_object: NapiCreateObject,
}

static NAPI: OnceLock<Option<Napi>> = OnceLock::new();

const INIT_SCRIPT: &str = r##"
(function() {
  const fs = require("fs");
  const appendFileSync = fs.appendFileSync.bind(fs);
  function mzRustLog(message) {
    try {
      appendFileSync("mz_rust.log", "[mz-js] " + String(message) + "\r\n");
    } catch (e) {}
  }
  globalThis.__mzRustLog = mzRustLog;
  mzRustLog("first script guard installed");
  return true;
})()
"##;

const FS_HOOK_SCRIPT: &str = r##"
(function() {
  const fs = require("fs");
  const path = require("path");
  const originals = globalThis.__mzFsOriginals || (globalThis.__mzFsOriginals = {
    writeFile: fs.writeFile,
    writeFileSync: fs.writeFileSync,
    appendFile: fs.appendFile,
    appendFileSync: fs.appendFileSync
  });
  function log(message) {
    try {
      originals.appendFileSync.call(fs, path.join(process.cwd(), "mz_rust.log"), "[mz-js] " + String(message) + "\r\n");
    } catch (e) {}
  }
  if (fs.__mzRustHooked) {
    log("fs hook already installed");
    return true;
  }
  function normalizeWin(p) {
    return String(p || "").replace(/\//g, "\\").toLowerCase();
  }
  function isAllowedFsWrite(file) {
    const full = path.resolve(process.cwd(), String(file));
    const fullLower = normalizeWin(full);
    const rootLower = normalizeWin(process.cwd());
    const base = path.basename(full).toLowerCase();
    return fullLower.indexOf("\\save\\") >= 0 ||
      base === "package.json" ||
      base === "c" ||
      base === "mz_rust.log" ||
      (fullLower.indexOf(rootLower + "\\data\\") === 0 && base.endsWith(".rmmzsave"));
  }
  function rejectIfNeeded(file) {
    if (!isAllowedFsWrite(file)) {
      const err = new Error("blocked by mz native fs policy: " + file);
      err.code = "EACCES";
      throw err;
    }
  }
  fs.writeFile = function(file, ...args) {
    try { rejectIfNeeded(file); } catch (e) {
      const cb = args.find(v => typeof v === "function");
      if (cb) return process.nextTick(cb, e);
      throw e;
    }
    return originals.writeFile.call(this, file, ...args);
  };
  fs.appendFile = function(file, ...args) {
    try { rejectIfNeeded(file); } catch (e) {
      const cb = args.find(v => typeof v === "function");
      if (cb) return process.nextTick(cb, e);
      throw e;
    }
    return originals.appendFile.call(this, file, ...args);
  };
  fs.writeFileSync = function(file, ...args) { rejectIfNeeded(file); return originals.writeFileSync.call(this, file, ...args); };
  fs.appendFileSync = function(file, ...args) { rejectIfNeeded(file); return originals.appendFileSync.call(this, file, ...args); };
  Object.defineProperty(fs, "__mzRustHooked", { value: true });
  log("fs write hooks installed");
  return true;
})()
"##;

const HOOK_SCRIPT: &str = r##"
(function() {
  const target = globalThis.__mzHookTarget;
  const native = globalThis.__mzNative;
  const fs = require("fs");
  const path = require("path");
  const originals = globalThis.__mzFsOriginals || (globalThis.__mzFsOriginals = {
    writeFile: fs.writeFile,
    writeFileSync: fs.writeFileSync,
    appendFile: fs.appendFile,
    appendFileSync: fs.appendFileSync
  });
  function log(message) {
    try {
      if (typeof globalThis.__mzRustLog === "function") {
        globalThis.__mzRustLog(message);
      } else {
        originals.appendFileSync.call(fs, path.join(process.cwd(), "mz_rust.log"), "[mz-js] " + String(message) + "\r\n");
      }
    } catch (e) {}
  }
  function normalizeUrlPath(url) {
    let p = String(url || "").split("?")[0].split("#")[0].replace(/\\/g, "/");
    try { p = decodeURIComponent(p); } catch (_) {}
    const out = [];
    for (const part of p.split("/")) {
      if (!part || part === ".") continue;
      if (part === "..") out.pop();
      else out.push(part);
    }
    return out.join("/");
  }
  function jsonVaultKey(url) {
    const p = normalizeUrlPath(url);
    const l = p.toLowerCase();
    const dx = l.indexOf("dataex/");
    if (dx >= 0) return p.slice(dx);
    const di = l.indexOf("data/");
    if (di >= 0) return p.slice(di + 5);
    const z = p.lastIndexOf("/");
    return z >= 0 ? p.slice(z + 1) : p;
  }
  function toArrayBuffer(value) {
    if (value instanceof ArrayBuffer) return value;
    const b = Buffer.from(String(value), "utf8");
    return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);
  }
  function toTargetArrayBuffer(value) {
    const source = new Uint8Array(value);
    const ArrayBufferCtor = target && target.ArrayBuffer ? target.ArrayBuffer : ArrayBuffer;
    const Uint8ArrayCtor = target && target.Uint8Array ? target.Uint8Array : Uint8Array;
    const out = new Uint8ArrayCtor(new ArrayBufferCtor(source.length));
    for (let i = 0; i < source.length; i++) out[i] = source[i];
    return out.buffer;
  }
  function installDiagnostics(obj) {
    if (obj && typeof obj.addEventListener === "function" && !obj.__mzDiagnosticsHooked) {
      try {
        obj.addEventListener("error", event => log("window error " + ((event && event.error && event.error.stack) || (event && event.message) || "")));
        obj.addEventListener("unhandledrejection", event => log("window unhandledrejection " + ((event && event.reason && event.reason.stack) || (event && event.reason) || "")));
        Object.defineProperty(obj, "__mzDiagnosticsHooked", { value: true });
      } catch (_) {}
    }
  }
  function installXhrHook(obj) {
    if (!obj || typeof obj.XMLHttpRequest !== "function") return;
    if (obj.XMLHttpRequest.__mzRustHooked) return;
    const NativeXMLHttpRequest = obj.XMLHttpRequest;
    log("installXhrHook target=" + (obj === globalThis ? "globalThis" : "object"));
    class MzXMLHttpRequest {
      constructor() {
        this._xhr = new NativeXMLHttpRequest();
        this._listeners = Object.create(null);
        this._intercept = false;
        this._method = "";
        this._url = "";
        this.readyState = 0;
        this.status = 0;
        this.statusText = "";
        this.response = null;
        this.responseText = "";
        this.responseType = "";
        this.responseURL = "";
        this.onreadystatechange = null;
        this.onload = null;
        this.onerror = null;
        this.onabort = null;
        this.ontimeout = null;
        this.onloadend = null;
        for (const type of ["readystatechange", "load", "error", "abort", "timeout", "loadend"]) {
          this._xhr.addEventListener(type, event => {
            if (this._intercept) return;
            this._copyNativeState(type);
            this._emit(type, event);
          });
        }
      }
      open(method, url, async = true, user, password) {
        this._method = String(method || "GET").toUpperCase();
        this._url = String(url || "");
        const lower = normalizeUrlPath(this._url).toLowerCase();
        this._intercept = this._method === "GET" && (/(^|\/)data(ex)?\/.+\.json$/.test(lower) || /(^|\/)img\/.+\.png_?$/.test(lower));
        log("xhr open method=" + this._method + " url=" + this._url + " intercept=" + this._intercept);
        this.readyState = 1;
        this.responseURL = this._url;
        this._emit("readystatechange");
        if (!this._intercept) return this._xhr.open(method, url, async, user, password);
      }
      overrideMimeType(mimeType) { this._mimeType = mimeType; if (!this._intercept && this._xhr.overrideMimeType) return this._xhr.overrideMimeType(mimeType); }
      setRequestHeader(name, value) { if (!this._intercept) return this._xhr.setRequestHeader(name, value); }
      getResponseHeader(name) {
        if (!this._intercept) return this._xhr.getResponseHeader(name);
        return String(name || "").toLowerCase() === "content-type" ? (this._contentType || null) : null;
      }
      getAllResponseHeaders() { if (!this._intercept) return this._xhr.getAllResponseHeaders(); return this._contentType ? "Content-Type: " + this._contentType + "\r\n" : ""; }
      addEventListener(type, listener) { (this._listeners[type] || (this._listeners[type] = [])).push(listener); }
      removeEventListener(type, listener) { const list = this._listeners[type]; if (!list) return; const i = list.indexOf(listener); if (i >= 0) list.splice(i, 1); }
      abort() { if (!this._intercept) return this._xhr.abort(); this.readyState = 0; this._emit("abort"); this._emit("loadend"); }
      send(...args) {
        if (!this._intercept) {
          this._xhr.responseType = this.responseType || "";
          return this._xhr.send(...args);
        }
        const lower = normalizeUrlPath(this._url).toLowerCase();
        this.readyState = 2;
        this._emit("readystatechange");
        setTimeout(() => {
          try {
            if (/(^|\/)data(ex)?\/.+\.json$/.test(lower)) {
              const text = native.loadVaultJsonText(jsonVaultKey(this._url));
              this.status = 200; this.statusText = "OK"; this.readyState = 4;
              this.responseText = text;
              this.response = this.responseType === "arraybuffer" ? toTargetArrayBuffer(toArrayBuffer(text)) : text;
              this._contentType = "application/json";
              log("xhr json ok url=" + this._url + " bytes=" + text.length);
            } else {
              const buf = native.readImageResource(this._url);
              if (!buf) throw new Error("image record not found");
              this.status = 200; this.statusText = "OK"; this.readyState = 4;
              this.response = toTargetArrayBuffer(buf); this.responseText = ""; this._contentType = "application/octet-stream";
              log("xhr image ok url=" + this._url + " bytes=" + buf.byteLength);
            }
            this._emit("readystatechange"); this._emit("load"); this._emit("loadend");
          } catch (e) {
            log("xhr fail url=" + this._url + " error=" + (e && e.message ? e.message : e));
            this.status = 404; this.statusText = "Not Found"; this.readyState = 4;
            this._emit("readystatechange"); this._emit("error", e); this._emit("loadend");
          }
        }, 0);
      }
      _emit(type, detail) {
        const event = { type, target: this, currentTarget: this, detail };
        const handler = this["on" + type];
        if (typeof handler === "function") handler.call(this, event);
        const list = this._listeners[type];
        if (list) for (const listener of list.slice()) {
          if (typeof listener === "function") listener.call(this, event);
          else if (listener && typeof listener.handleEvent === "function") listener.handleEvent(event);
        }
      }
      _copyNativeState(eventType) {
        try { this.readyState = this._xhr.readyState; } catch (_) {}
        try { this.status = this._xhr.status; } catch (_) {}
        try { this.statusText = this._xhr.statusText; } catch (_) {}
        try { this.response = this._xhr.response; } catch (_) {}
        try { const rt = String(this._xhr.responseType || ""); this.responseText = (rt === "" || rt === "text") ? this._xhr.responseText : ""; } catch (e) { this.responseText = ""; }
        try { this.responseURL = this._xhr.responseURL; } catch (_) {}
      }
    }
    Object.defineProperty(MzXMLHttpRequest, "__mzRustHooked", { value: true });
    for (const [name, value] of [["UNSENT",0],["OPENED",1],["HEADERS_RECEIVED",2],["LOADING",3],["DONE",4]]) {
      Object.defineProperty(MzXMLHttpRequest, name, { value, enumerable: true });
      Object.defineProperty(MzXMLHttpRequest.prototype, name, { value, enumerable: true });
    }
    obj.XMLHttpRequest = MzXMLHttpRequest;
  }
  function installFetchHook(obj) {
    if (!obj || typeof obj.fetch !== "function" || obj.fetch.__mzRustHooked) return;
    const nativeFetch = obj.fetch;
    const hookedFetch = function(input, init) {
      const url = typeof input === "string" ? input : input && input.url;
      const lower = normalizeUrlPath(url).toLowerCase();
      if (/(^|\/)data(ex)?\/.+\.json$/.test(lower)) {
        try { return Promise.resolve(new Response(native.loadVaultJsonText(jsonVaultKey(url)), { status: 200, headers: { "content-type": "application/json" } })); }
        catch (e) { return Promise.reject(e); }
      }
      return nativeFetch.call(this, input, init);
    };
    Object.defineProperty(hookedFetch, "__mzRustHooked", { value: true });
    obj.fetch = hookedFetch;
  }
  log("installWindowHooks called hasTarget=" + !!target + " hasXHR=" + !!(target && target.XMLHttpRequest));
  installDiagnostics(target);
  installXhrHook(target);
  installFetchHook(target);
  log("installWindowHooks done hooked=" + !!(target && target.XMLHttpRequest && target.XMLHttpRequest.__mzRustHooked));
  return true;
})()
"##;

const AUTO_HOOK_SCRIPT: &str = r##"
(function() {
  const native = globalThis.__mzNative;
  if (!native || typeof native.installWindowHooks !== "function") return false;
  function install(target) {
    try {
      if (target) native.installWindowHooks(target);
    } catch (e) {
      try {
        if (typeof globalThis.__mzRustLog === "function") {
          globalThis.__mzRustLog("auto hook target failed " + (e && e.message ? e.message : e));
        }
      } catch (_) {}
    }
  }
  install(globalThis);
  try { if (typeof window !== "undefined") install(window); } catch (_) {}
  try {
    if (typeof nw === "object" && nw.Window) {
      const win = nw.Window.get();
      if (win && win.window) install(win.window);
    }
  } catch (_) {}
  try {
    setTimeout(function() {
      install(globalThis);
      try { if (typeof window !== "undefined") install(window); } catch (_) {}
      try {
        if (typeof nw === "object" && nw.Window) {
          const win = nw.Window.get();
          if (win && win.window) install(win.window);
        }
      } catch (_) {}
    }, 0);
  } catch (_) {}
  return true;
})()
"##;

fn init_console() {
    unsafe {
        AllocConsole();
        SetConsoleTitleA(c"mz.node rust log".as_ptr() as _);
    }
}

fn log(message: &str) {
    let mut line = String::from("[mz-rust] ");
    line.push_str(message);
    line.push_str("\r\n");
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open("mz_rust.log") {
        let _ = file.write_all(line.as_bytes());
    }
    unsafe {
        let handle = GetStdHandle(STD_OUTPUT_HANDLE);
        if handle != std::ptr::null_mut() && handle != INVALID_HANDLE_VALUE {
            let mut written = 0;
            WriteConsoleA(handle, line.as_ptr() as _, line.len() as u32, &mut written, null_mut());
        }
    }
}

unsafe fn module(name: &'static CStr) -> HMODULE {
    unsafe { GetModuleHandleA(name.as_ptr() as _) }
}

unsafe fn current_process_module() -> HMODULE {
    unsafe { GetModuleHandleA(null()) }
}

unsafe fn proc_address(module: HMODULE, name: &'static CStr) -> *const c_void {
    if module == std::ptr::null_mut() {
        return null();
    }
    unsafe {
        match GetProcAddress(module, name.as_ptr() as _) {
            Some(p) => p as *const c_void,
            None => null(),
        }
    }
}

unsafe fn resolve_symbol(name: &'static CStr) -> *const c_void {
    for module_name in [c"node.dll", c"nw.dll"] {
        let p = unsafe { proc_address(module(module_name), name) };
        if !p.is_null() {
            return p;
        }
    }
    let p = unsafe { proc_address(current_process_module(), name) };
    if !p.is_null() {
        return p;
    }
    null()
}

unsafe fn load_napi() -> Option<Napi> {
    unsafe {
        let create_string_utf8 = resolve_symbol(c"napi_create_string_utf8");
        let run_script = resolve_symbol(c"napi_run_script");
        let get_named_property = resolve_symbol(c"napi_get_named_property");
        let set_named_property = resolve_symbol(c"napi_set_named_property");
        let get_global = resolve_symbol(c"napi_get_global");
        let create_function = resolve_symbol(c"napi_create_function");
        let get_cb_info = resolve_symbol(c"napi_get_cb_info");
        let get_value_string_utf8 = resolve_symbol(c"napi_get_value_string_utf8");
        let create_arraybuffer = resolve_symbol(c"napi_create_arraybuffer");
        let get_null = resolve_symbol(c"napi_get_null");
        let create_int32 = resolve_symbol(c"napi_create_int32");
        let call_function = resolve_symbol(c"napi_call_function");
        let throw_error = resolve_symbol(c"napi_throw_error");
        let get_boolean = resolve_symbol(c"napi_get_boolean");
        let create_object = resolve_symbol(c"napi_create_object");

        for (name, ptr) in [
            ("napi_create_string_utf8", create_string_utf8),
            ("napi_run_script", run_script),
            ("napi_get_named_property", get_named_property),
            ("napi_set_named_property", set_named_property),
            ("napi_get_global", get_global),
            ("napi_create_function", create_function),
            ("napi_get_cb_info", get_cb_info),
            ("napi_get_value_string_utf8", get_value_string_utf8),
            ("napi_create_arraybuffer", create_arraybuffer),
            ("napi_get_null", get_null),
            ("napi_create_int32", create_int32),
            ("napi_call_function", call_function),
            ("napi_throw_error", throw_error),
            ("napi_get_boolean", get_boolean),
            ("napi_create_object", create_object),
        ] {
            if ptr.is_null() {
                log(&format!("missing Node-API symbol {name}"));
            } else {
                log(&format!("loaded Node-API symbol {name}"));
            }
        }

        if create_string_utf8.is_null()
            || run_script.is_null()
            || get_named_property.is_null()
            || set_named_property.is_null()
            || get_global.is_null()
            || create_function.is_null()
            || get_cb_info.is_null()
            || get_value_string_utf8.is_null()
            || create_arraybuffer.is_null()
            || get_null.is_null()
            || create_int32.is_null()
            || call_function.is_null()
            || throw_error.is_null()
            || get_boolean.is_null()
            || create_object.is_null()
        {
            None
        } else {
            Some(Napi {
                create_string_utf8: transmute::<*const c_void, NapiCreateStringUtf8>(create_string_utf8),
                run_script: transmute::<*const c_void, NapiRunScript>(run_script),
                get_named_property: transmute::<*const c_void, NapiGetNamedProperty>(get_named_property),
                set_named_property: transmute::<*const c_void, NapiSetNamedProperty>(set_named_property),
                get_global: transmute::<*const c_void, NapiGetGlobal>(get_global),
                create_function: transmute::<*const c_void, NapiCreateFunction>(create_function),
                get_cb_info: transmute::<*const c_void, NapiGetCbInfo>(get_cb_info),
                get_value_string_utf8: transmute::<*const c_void, NapiGetValueStringUtf8>(get_value_string_utf8),
                create_arraybuffer: transmute::<*const c_void, NapiCreateArraybuffer>(create_arraybuffer),
                get_null: transmute::<*const c_void, NapiGetNull>(get_null),
                create_int32: transmute::<*const c_void, NapiCreateInt32>(create_int32),
                call_function: transmute::<*const c_void, NapiCallFunction>(call_function),
                throw_error: transmute::<*const c_void, NapiThrowError>(throw_error),
                get_boolean: transmute::<*const c_void, NapiGetBoolean>(get_boolean),
                create_object: transmute::<*const c_void, NapiCreateObject>(create_object),
            })
        }
    }
}

fn napi() -> Option<&'static Napi> {
    NAPI.get_or_init(|| unsafe { load_napi() }).as_ref()
}

unsafe fn create_string(env: NapiEnv, text: &str) -> Option<NapiValue> {
    let napi = napi()?;
    let c = CString::new(text).ok()?;
    let mut value = null_mut();
    let status = unsafe { (napi.create_string_utf8)(env, c.as_ptr(), NAPI_AUTO_LENGTH, &mut value) };
    if status == NAPI_OK && !value.is_null() {
        Some(value)
    } else {
        log(&format!("napi_create_string_utf8 failed status={status}"));
        None
    }
}

unsafe fn get_named(env: NapiEnv, object: NapiValue, name: &'static CStr) -> Option<NapiValue> {
    let napi = napi()?;
    let mut value = null_mut();
    let status = unsafe { (napi.get_named_property)(env, object, name.as_ptr(), &mut value) };
    if status == NAPI_OK && !value.is_null() {
        Some(value)
    } else {
        log(&format!("napi_get_named_property({}) failed status={status}", name.to_string_lossy()));
        None
    }
}

unsafe fn set_named(env: NapiEnv, object: NapiValue, name: &'static CStr, value: NapiValue) {
    if let Some(napi) = napi() {
        let status = unsafe { (napi.set_named_property)(env, object, name.as_ptr(), value) };
        log(&format!("napi_set_named_property({}) status={status}", name.to_string_lossy()));
    }
}

unsafe fn get_global(env: NapiEnv) -> Option<NapiValue> {
    let napi = napi()?;
    let mut value = null_mut();
    let status = unsafe { (napi.get_global)(env, &mut value) };
    if status == NAPI_OK && !value.is_null() { Some(value) } else { None }
}

unsafe fn get_null(env: NapiEnv) -> NapiValue {
    let mut value = null_mut();
    if let Some(napi) = napi() {
        let _ = unsafe { (napi.get_null)(env, &mut value) };
    }
    value
}

unsafe fn get_args(env: NapiEnv, info: NapiCallbackInfo, max: usize) -> (Vec<NapiValue>, NapiValue) {
    let Some(napi) = napi() else {
        return (Vec::new(), null_mut());
    };
    let mut argc = max;
    let mut argv = vec![null_mut(); max];
    let mut this_arg = null_mut();
    let status = unsafe { (napi.get_cb_info)(env, info, &mut argc, argv.as_mut_ptr(), &mut this_arg, null_mut()) };
    if status != NAPI_OK {
        return (Vec::new(), this_arg);
    }
    argv.truncate(argc);
    (argv, this_arg)
}

unsafe fn value_to_string(env: NapiEnv, value: NapiValue) -> Result<String, String> {
    let napi = napi().ok_or_else(|| "N-API unavailable".to_string())?;
    let mut len = 0usize;
    let status = unsafe { (napi.get_value_string_utf8)(env, value, null_mut(), 0, &mut len) };
    if status != NAPI_OK {
        return Err(format!("napi_get_value_string_utf8 length failed status={status}"));
    }
    let mut buf = vec![0u8; len + 1];
    let status = unsafe { (napi.get_value_string_utf8)(env, value, buf.as_mut_ptr() as *mut c_char, buf.len(), &mut len) };
    if status != NAPI_OK {
        return Err(format!("napi_get_value_string_utf8 failed status={status}"));
    }
    buf.truncate(len);
    String::from_utf8(buf).map_err(|e| format!("utf8 argument failed: {e}"))
}

unsafe fn create_arraybuffer(env: NapiEnv, bytes: &[u8]) -> Option<NapiValue> {
    let napi = napi()?;
    let mut data = null_mut();
    let mut value = null_mut();
    let status = unsafe { (napi.create_arraybuffer)(env, bytes.len(), &mut data, &mut value) };
    if status != NAPI_OK || value.is_null() || (data.is_null() && !bytes.is_empty()) {
        log(&format!("napi_create_arraybuffer failed status={status}"));
        return None;
    }
    if !bytes.is_empty() {
        unsafe { copy_nonoverlapping(bytes.as_ptr(), data as *mut u8, bytes.len()) };
    }
    Some(value)
}

unsafe fn create_int32(env: NapiEnv, value: i32) -> NapiValue {
    let mut out = null_mut();
    if let Some(napi) = napi() {
        let _ = unsafe { (napi.create_int32)(env, value, &mut out) };
    }
    out
}

unsafe fn create_bool(env: NapiEnv, value: bool) -> NapiValue {
    let mut out = null_mut();
    if let Some(napi) = napi() {
        let _ = unsafe { (napi.get_boolean)(env, value, &mut out) };
    }
    out
}

unsafe fn throw_error(env: NapiEnv, message: &str) -> NapiValue {
    log(&format!("throw JS error: {message}"));
    if let Some(napi) = napi() {
        if let Ok(cmsg) = CString::new(message) {
            let _ = unsafe { (napi.throw_error)(env, null(), cmsg.as_ptr()) };
        }
    }
    unsafe { get_null(env) }
}

unsafe fn export_function(env: NapiEnv, exports: NapiValue, name: &'static CStr, callback: NapiCallback) {
    if let Some(napi) = napi() {
        let mut func = null_mut();
        let status = unsafe { (napi.create_function)(env, name.as_ptr(), NAPI_AUTO_LENGTH, callback, null_mut(), &mut func) };
        log(&format!("napi_create_function({}) status={status}", name.to_string_lossy()));
        if status == NAPI_OK && !func.is_null() {
            unsafe { set_named(env, exports, name, func) };
        }
    }
}

unsafe extern "C" fn cb_load_vault_json_text(env: NapiEnv, info: NapiCallbackInfo) -> NapiValue {
    let (args, _) = unsafe { get_args(env, info, 1) };
    let Some(first) = args.first().copied() else {
        return unsafe { throw_error(env, "loadVaultJsonText requires a key") };
    };
    let key = match unsafe { value_to_string(env, first) } {
        Ok(v) => v,
        Err(e) => return unsafe { throw_error(env, &e) },
    };
    match resource::load_vault_json_text(&key) {
        Ok(text) => unsafe { create_string(env, &text).unwrap_or_else(|| get_null(env)) },
        Err(e) => unsafe { throw_error(env, &e) },
    }
}

unsafe extern "C" fn cb_load_vault_json(env: NapiEnv, info: NapiCallbackInfo) -> NapiValue {
    let text_value = unsafe { cb_load_vault_json_text(env, info) };
    if text_value.is_null() {
        return text_value;
    }
    let Some(global) = (unsafe { get_global(env) }) else {
        return unsafe { get_null(env) };
    };
    unsafe { set_named(env, global, c"__mzJsonParseText", text_value) };
    let Some(script) = (unsafe { create_string(env, "JSON.parse(globalThis.__mzJsonParseText)") }) else {
        return unsafe { get_null(env) };
    };
    let mut parsed = null_mut();
    let status = unsafe { (napi().unwrap().run_script)(env, script, &mut parsed) };
    if status == NAPI_OK && !parsed.is_null() {
        parsed
    } else {
        unsafe { throw_error(env, &format!("JSON.parse run_script failed status={status}")) }
    }
}

unsafe extern "C" fn cb_read_image_resource(env: NapiEnv, info: NapiCallbackInfo) -> NapiValue {
    let (args, _) = unsafe { get_args(env, info, 1) };
    let Some(first) = args.first().copied() else {
        return unsafe { get_null(env) };
    };
    let key = match unsafe { value_to_string(env, first) } {
        Ok(v) => v,
        Err(e) => return unsafe { throw_error(env, &e) },
    };
    match resource::read_image_resource(&key) {
        Ok(Some(bytes)) => unsafe { create_arraybuffer(env, &bytes).unwrap_or_else(|| get_null(env)) },
        Ok(None) => unsafe { get_null(env) },
        Err(e) => unsafe { throw_error(env, &e) },
    }
}

unsafe extern "C" fn cb_img_job_wire10_async(env: NapiEnv, info: NapiCallbackInfo) -> NapiValue {
    let (args, this_arg) = unsafe { get_args(env, info, 3) };
    if args.len() < 3 {
        return unsafe { get_null(env) };
    }
    let key = match unsafe { value_to_string(env, args[0]) } {
        Ok(v) => v,
        Err(_) => return unsafe { get_null(env) },
    };
    let callback = args[2];
    let mut cb_args = [null_mut(); 2];
    match resource::read_image_resource(&key) {
        Ok(Some(bytes)) if !bytes.is_empty() => {
            cb_args[0] = unsafe { create_arraybuffer(env, &bytes).unwrap_or_else(|| get_null(env)) };
            cb_args[1] = unsafe { get_null(env) };
        }
        Ok(_) => {
            cb_args[0] = unsafe { get_null(env) };
            cb_args[1] = unsafe { create_int32(env, 0x23) };
        }
        Err(e) => {
            log(&format!("ImgJobWire10Async failed key={key} error={e}"));
            cb_args[0] = unsafe { get_null(env) };
            cb_args[1] = unsafe { create_int32(env, 0xf9) };
        }
    }
    if let Some(napi) = napi() {
        let mut result = null_mut();
        let _ = unsafe { (napi.call_function)(env, this_arg, callback, 2, cb_args.as_ptr(), &mut result) };
    }
    unsafe { get_null(env) }
}

unsafe extern "C" fn cb_is_allowed_fs_write(env: NapiEnv, info: NapiCallbackInfo) -> NapiValue {
    let (args, _) = unsafe { get_args(env, info, 1) };
    let path = args
        .first()
        .copied()
        .and_then(|v| unsafe { value_to_string(env, v).ok() })
        .unwrap_or_default();
    unsafe { create_bool(env, resource::is_allowed_fs_write(&path)) }
}

unsafe extern "C" fn cb_scan_environment(env: NapiEnv, _info: NapiCallbackInfo) -> NapiValue {
    let Some(napi) = napi() else {
        return unsafe { get_null(env) };
    };
    let mut obj = null_mut();
    let status = unsafe { (napi.create_object)(env, &mut obj) };
    if status == NAPI_OK && !obj.is_null() {
        unsafe { set_named(env, obj, c"ok", create_bool(env, true)) };
        obj
    } else {
        unsafe { get_null(env) }
    }
}

unsafe extern "C" fn cb_install_window_hooks(env: NapiEnv, info: NapiCallbackInfo) -> NapiValue {
    let (args, _) = unsafe { get_args(env, info, 1) };
    let Some(target) = args.first().copied() else {
        return unsafe { create_bool(env, false) };
    };
    let Some(global) = (unsafe { get_global(env) }) else {
        return unsafe { create_bool(env, false) };
    };
    unsafe { set_named(env, global, c"__mzHookTarget", target) };
    let Some(script) = (unsafe { create_string(env, HOOK_SCRIPT) }) else {
        return unsafe { create_bool(env, false) };
    };
    let mut result = null_mut();
    let status = unsafe { (napi().unwrap().run_script)(env, script, &mut result) };
    log(&format!("installWindowHooks run_script status={status}"));
    if status == NAPI_OK && !result.is_null() {
        result
    } else {
        unsafe { create_bool(env, false) }
    }
}

unsafe fn run_script_named(env: NapiEnv, phase: &str, script_text: &str) -> Option<NapiValue> {
    let Some(napi) = napi() else {
        log(&format!("{phase}: Node-API unavailable"));
        return None;
    };
    let Some(script) = (unsafe { create_string(env, script_text) }) else {
        log(&format!("{phase}: create script string failed"));
        return None;
    };
    let mut result = null_mut();
    let status = unsafe { (napi.run_script)(env, script, &mut result) };
    log(&format!("{phase}: napi_run_script status={status} result_is_null={}", result.is_null()));
    if status == NAPI_OK && !result.is_null() { Some(result) } else { None }
}

fn initialize_runtime_state() {
    log("Runtime::installCleanup / initializeState / Crypto::initializeTables / SystemConfig::initialize");
}

fn register_dispatch_handlers() {
    for (slot, name) in [
        (0x0, "Resource::handler00"),
        (0x1, "Resource::handler01"),
        (0x4, "Resource::handler04"),
        (0x5, "Resource::handler05"),
        (0x7, "sub_180006BAF"),
        (0x8, "Resource::readFile"),
        (0x9, "Resource::handler09"),
        (0xa, "Resource::handler0A"),
        (0xb, "Resource::handler0B"),
        (0xe, "Resource::handler0E"),
        (0xf, "sub_180006BAF"),
    ] {
        log(&format!("Dispatch::setHandler slot=0x{slot:x} handler={name}"));
    }
    log("DispatchGuard::checkHandlerCode/checkRegisteredHandlerSlot");
}

unsafe fn install_fs_write_hooks(env: NapiEnv) {
    log("FsHook::installWriteHooks begin");
    let _ = unsafe { run_script_named(env, "FsHook::installWriteHooks", FS_HOOK_SCRIPT) };
}

unsafe fn define_core_exports(env: NapiEnv, exports: NapiValue) {
    log("napi_define_properties core exports begin");
    unsafe {
        export_function(env, exports, c"loadVaultJson", cb_load_vault_json);
        export_function(env, exports, c"loadVaultJsonText", cb_load_vault_json_text);
        export_function(env, exports, c"readImageResource", cb_read_image_resource);
        export_function(env, exports, c"scanEnvironment", cb_scan_environment);
        export_function(env, exports, c"isAllowedFsWrite", cb_is_allowed_fs_write);
        export_function(env, exports, c"installWindowHooks", cb_install_window_hooks);
        if let Some(global) = get_global(env) {
            set_named(env, global, c"__mzNative", exports);
        }
    }
}

unsafe fn install_first_script_guard(env: NapiEnv, _exports: NapiValue) {
    log("JsRuntime::installFirstScriptGuard begin");
    let _ = unsafe { run_script_named(env, "JsRuntime::installFirstScriptGuard", INIT_SCRIPT) };
}

unsafe fn install_second_script_guard(env: NapiEnv, exports: NapiValue) -> NapiValue {
    log("JsRuntime::installSecondScriptGuard begin");
    let _ = unsafe { run_script_named(env, "JsRuntime::installSecondScriptGuard", AUTO_HOOK_SCRIPT) };
    exports
}

unsafe fn install_img_job_wire(env: NapiEnv, exports: NapiValue, second_guard_result: NapiValue) {
    log(&format!(
        "Addon::installImgJobWire begin second_guard_result_is_null={}",
        second_guard_result.is_null()
    ));
    unsafe {
        export_function(env, second_guard_result, c"ImgJobWire10Async", cb_img_job_wire10_async);
        if let Some(func) = get_named(env, exports, c"ImgJobWire10Async") {
            if let Some(global) = get_global(env) {
                set_named(env, global, c"__mzIw10", func);
                log("Addon::installImgJobWire installed global.__mzIw10 from exports.ImgJobWire10Async");
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn napi_register_module_v1(env: NapiEnv, exports: NapiValue) -> NapiValue {
    init_console();
    let root = resource::init_root();
    reset_logs(&root);
    log("module init enter");
    log(&format!("resource root={}", root.display()));

    if napi().is_none() {
        log("Node-API symbol resolution failed; returning original exports");
        return exports;
    }

    initialize_runtime_state();
    register_dispatch_handlers();

    unsafe {
        install_fs_write_hooks(env);
        define_core_exports(env, exports);
        install_first_script_guard(env, exports);
        let second_guard_result = install_second_script_guard(env, exports);
        install_img_job_wire(env, exports, second_guard_result);
    }

    log("module init complete");
    exports
}

fn reset_logs(root: &std::path::Path) {
    let mut paths = Vec::new();
    paths.push(std::path::PathBuf::from("mz_rust.log"));
    paths.push(std::path::PathBuf::from("mz_js.log"));
    paths.push(std::path::PathBuf::from("CONOUT$"));
    paths.push(root.join("mz_rust.log"));
    paths.push(root.join("mz_js.log"));
    paths.push(root.join("CONOUT$"));
    for path in paths {
        let _ = remove_file(path);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn node_api_module_get_api_version_v1() -> i32 {
    4
}
