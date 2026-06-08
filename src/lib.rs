mod resource;

use std::ffi::{CStr, CString, c_char, c_void};
use std::fs::{OpenOptions, remove_file};
use std::io::Write;
use std::mem::transmute;
use std::ptr::{copy_nonoverlapping, null, null_mut};
use std::sync::OnceLock;
use std::thread;

use windows_sys::Win32::Foundation::{HMODULE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Console::{AllocConsole, GetStdHandle, STD_OUTPUT_HANDLE, SetConsoleTitleA, WriteConsoleA};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

type NapiEnv = *mut c_void;
type NapiValue = *mut c_void;
type NapiCallbackInfo = *mut c_void;
type NapiThreadsafeFunction = *mut c_void;
type NapiStatus = i32;

const NAPI_OK: NapiStatus = 0;
const NAPI_AUTO_LENGTH: usize = usize::MAX;
const OPCODE_ENV_CHECK: i32 = 0x352b4710;
const OPCODE_LOAD_JSON: i32 = 0x1ed53fef;

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
type NapiCreateUint32 = unsafe extern "C" fn(NapiEnv, u32, *mut NapiValue) -> NapiStatus;
type NapiCallFunction = unsafe extern "C" fn(NapiEnv, NapiValue, NapiValue, usize, *const NapiValue, *mut NapiValue) -> NapiStatus;
type NapiThrowError = unsafe extern "C" fn(NapiEnv, *const c_char, *const c_char) -> NapiStatus;
type NapiGetBoolean = unsafe extern "C" fn(NapiEnv, bool, *mut NapiValue) -> NapiStatus;
type NapiCreateObject = unsafe extern "C" fn(NapiEnv, *mut NapiValue) -> NapiStatus;
type NapiGetElement = unsafe extern "C" fn(NapiEnv, NapiValue, u32, *mut NapiValue) -> NapiStatus;
type NapiGetValueInt32 = unsafe extern "C" fn(NapiEnv, NapiValue, *mut i32) -> NapiStatus;
type NapiGetUndefined = unsafe extern "C" fn(NapiEnv, *mut NapiValue) -> NapiStatus;
type NapiTypeof = unsafe extern "C" fn(NapiEnv, NapiValue, *mut i32) -> NapiStatus;
type NapiThreadsafeFunctionCallJs = unsafe extern "C" fn(NapiEnv, NapiValue, *mut c_void, *mut c_void);
type NapiCreateThreadsafeFunction = unsafe extern "C" fn(NapiEnv, NapiValue, NapiValue, NapiValue, usize, usize, *mut c_void, *mut c_void, *mut c_void, Option<NapiThreadsafeFunctionCallJs>, *mut NapiThreadsafeFunction) -> NapiStatus;
type NapiCallThreadsafeFunction = unsafe extern "C" fn(NapiThreadsafeFunction, *mut c_void, i32) -> NapiStatus;
type NapiReleaseThreadsafeFunction = unsafe extern "C" fn(NapiThreadsafeFunction, i32) -> NapiStatus;

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
    create_uint32: NapiCreateUint32,
    call_function: NapiCallFunction,
    throw_error: NapiThrowError,
    get_boolean: NapiGetBoolean,
    create_object: NapiCreateObject,
    get_element: NapiGetElement,
    get_value_int32: NapiGetValueInt32,
    get_undefined: NapiGetUndefined,
    type_of: NapiTypeof,
    create_threadsafe_function: NapiCreateThreadsafeFunction,
    call_threadsafe_function: NapiCallThreadsafeFunction,
    release_threadsafe_function: NapiReleaseThreadsafeFunction,
}

struct ImgJobResult {
    bytes: Option<Vec<u8>>,
    error_code: u32,
}

static NAPI: OnceLock<Option<Napi>> = OnceLock::new();

const INIT_SCRIPT: &str = include_str!("../js/init.js");

const FS_HOOK_SCRIPT: &str = include_str!("../js/fs_hook.js");

const JSON_HOOK_SCRIPT: &str = include_str!("../js/json_hook.js");

const HOOK_SCRIPT: &str = include_str!("../js/window_hook.js");

const AUTO_HOOK_SCRIPT: &str = include_str!("../js/auto_hook.js");

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
        let create_uint32 = resolve_symbol(c"napi_create_uint32");
        let call_function = resolve_symbol(c"napi_call_function");
        let throw_error = resolve_symbol(c"napi_throw_error");
        let get_boolean = resolve_symbol(c"napi_get_boolean");
        let create_object = resolve_symbol(c"napi_create_object");
        let get_element = resolve_symbol(c"napi_get_element");
        let get_value_int32 = resolve_symbol(c"napi_get_value_int32");
        let get_undefined = resolve_symbol(c"napi_get_undefined");
        let type_of = resolve_symbol(c"napi_typeof");
        let create_threadsafe_function = resolve_symbol(c"napi_create_threadsafe_function");
        let call_threadsafe_function = resolve_symbol(c"napi_call_threadsafe_function");
        let release_threadsafe_function = resolve_symbol(c"napi_release_threadsafe_function");

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
            ("napi_create_uint32", create_uint32),
            ("napi_call_function", call_function),
            ("napi_throw_error", throw_error),
            ("napi_get_boolean", get_boolean),
            ("napi_create_object", create_object),
            ("napi_get_element", get_element),
            ("napi_get_value_int32", get_value_int32),
            ("napi_get_undefined", get_undefined),
            ("napi_typeof", type_of),
            ("napi_create_threadsafe_function", create_threadsafe_function),
            ("napi_call_threadsafe_function", call_threadsafe_function),
            ("napi_release_threadsafe_function", release_threadsafe_function),
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
            || create_uint32.is_null()
            || call_function.is_null()
            || throw_error.is_null()
            || get_boolean.is_null()
            || create_object.is_null()
            || get_element.is_null()
            || get_value_int32.is_null()
            || get_undefined.is_null()
            || type_of.is_null()
            || create_threadsafe_function.is_null()
            || call_threadsafe_function.is_null()
            || release_threadsafe_function.is_null()
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
                create_uint32: transmute::<*const c_void, NapiCreateUint32>(create_uint32),
                call_function: transmute::<*const c_void, NapiCallFunction>(call_function),
                throw_error: transmute::<*const c_void, NapiThrowError>(throw_error),
                get_boolean: transmute::<*const c_void, NapiGetBoolean>(get_boolean),
                create_object: transmute::<*const c_void, NapiCreateObject>(create_object),
                get_element: transmute::<*const c_void, NapiGetElement>(get_element),
                get_value_int32: transmute::<*const c_void, NapiGetValueInt32>(get_value_int32),
                get_undefined: transmute::<*const c_void, NapiGetUndefined>(get_undefined),
                type_of: transmute::<*const c_void, NapiTypeof>(type_of),
                create_threadsafe_function: transmute::<*const c_void, NapiCreateThreadsafeFunction>(create_threadsafe_function),
                call_threadsafe_function: transmute::<*const c_void, NapiCallThreadsafeFunction>(call_threadsafe_function),
                release_threadsafe_function: transmute::<*const c_void, NapiReleaseThreadsafeFunction>(release_threadsafe_function),
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

unsafe fn get_undefined(env: NapiEnv) -> NapiValue {
    let mut value = null_mut();
    if let Some(napi) = napi() {
        let _ = unsafe { (napi.get_undefined)(env, &mut value) };
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

unsafe fn value_to_i32(env: NapiEnv, value: NapiValue) -> Result<i32, String> {
    let napi = napi().ok_or_else(|| "N-API unavailable".to_string())?;
    let mut out = 0i32;
    let status = unsafe { (napi.get_value_int32)(env, value, &mut out) };
    if status == NAPI_OK { Ok(out) } else { Err(format!("napi_get_value_int32 failed status={status}")) }
}

unsafe fn get_element(env: NapiEnv, value: NapiValue, index: u32) -> Option<NapiValue> {
    let napi = napi()?;
    let mut out = null_mut();
    let status = unsafe { (napi.get_element)(env, value, index, &mut out) };
    if status == NAPI_OK && !out.is_null() {
        Some(out)
    } else {
        log(&format!("napi_get_element({index}) failed status={status}"));
        None
    }
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

unsafe fn create_uint32(env: NapiEnv, value: u32) -> NapiValue {
    let mut out = null_mut();
    if let Some(napi) = napi() {
        let _ = unsafe { (napi.create_uint32)(env, value, &mut out) };
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

unsafe fn value_is_function(env: NapiEnv, value: NapiValue) -> bool {
    let Some(napi) = napi() else {
        return false;
    };
    let mut typ = 0i32;
    let status = unsafe { (napi.type_of)(env, value, &mut typ) };
    status == NAPI_OK && typ == 7
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

unsafe fn load_vault_json_value(env: NapiEnv, key: &str) -> NapiValue {
    let text = match resource::load_vault_json_text(key) {
        Ok(text) => text,
        Err(e) => {
            log(&format!("loadVaultJson null key={key} error={e}"));
            return unsafe { get_null(env) };
        }
    };
    let Some(text_value) = (unsafe { create_string(env, &text) }) else {
        return unsafe { get_null(env) };
    };
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
        log(&format!("loadVaultJson object ok key={key}"));
        parsed
    } else {
        log(&format!("loadVaultJson parse null key={key} status={status}"));
        unsafe { get_null(env) }
    }
}

unsafe extern "C" fn cb_load_vault_json(env: NapiEnv, info: NapiCallbackInfo) -> NapiValue {
    let (args, _) = unsafe { get_args(env, info, 1) };
    let Some(first) = args.first().copied() else {
        return unsafe { get_null(env) };
    };
    let key = match unsafe { value_to_string(env, first) } {
        Ok(v) => v,
        Err(e) => {
            log(&format!("loadVaultJson null argument error={e}"));
            return unsafe { get_null(env) };
        }
    };
    unsafe { load_vault_json_value(env, &key) }
}

unsafe extern "C" fn cb_dispatch(env: NapiEnv, info: NapiCallbackInfo) -> NapiValue {
    let (args, _) = unsafe { get_args(env, info, 2) };
    let Some(first) = args.first().copied() else {
        return unsafe { throw_error(env, "dispatch requires an opcode array") };
    };
    let opcode_value = unsafe { get_element(env, first, 0).unwrap_or(first) };
    let opcode = match unsafe { value_to_i32(env, opcode_value) } {
        Ok(v) => v,
        Err(e) => return unsafe { throw_error(env, &e) },
    };
    match opcode {
        OPCODE_ENV_CHECK => {
            log("dispatcher opcode=0x352b4710 slot=0 handler00");
            unsafe { create_bool(env, true) }
        }
        OPCODE_LOAD_JSON => {
            let key_value = if args.len() >= 2 {
                args[1]
            } else {
                match unsafe { get_element(env, first, 1) } {
                    Some(v) => v,
                    None => return unsafe { get_null(env) },
                }
            };
            let key = match unsafe { value_to_string(env, key_value) } {
                Ok(v) => v,
                Err(e) => {
                    log(&format!("dispatcher loadVaultJson null argument error={e}"));
                    return unsafe { get_null(env) };
                }
            };
            log(&format!("dispatcher opcode=0x1ed53fef slot=9 loadVaultJson key={key}"));
            unsafe { load_vault_json_value(env, &key) }
        }
        _ => unsafe { throw_error(env, &format!("unsupported dispatcher opcode=0x{opcode:08x}")) },
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
        Ok(bytes) if !bytes.is_empty() => unsafe { create_arraybuffer(env, &bytes).unwrap_or_else(|| get_null(env)) },
        Ok(_) => unsafe { get_null(env) },
        Err(e) => {
            log(&format!("readImageResource null key={key} code=0x{:02x} error={}", e.code(), e.message()));
            unsafe { get_null(env) }
        }
    }
}

unsafe extern "C" fn img_job_deliver_to_js(env: NapiEnv, js_callback: NapiValue, _context: *mut c_void, data: *mut c_void) {
    if data.is_null() {
        return;
    }
    let result = unsafe { Box::from_raw(data as *mut ImgJobResult) };
    if env.is_null() || js_callback.is_null() {
        return;
    }

    let null_value = unsafe { get_null(env) };
    let mut cb_args = [null_value; 2];
    if let Some(bytes) = result.bytes.as_deref() {
        if !bytes.is_empty() {
            if let Some(buffer) = unsafe { create_arraybuffer(env, bytes) } {
                cb_args[0] = buffer;
                cb_args[1] = null_value;
            } else {
                cb_args[0] = null_value;
                cb_args[1] = unsafe { create_uint32(env, 0xfc) };
            }
        } else {
            cb_args[0] = null_value;
            cb_args[1] = unsafe { create_uint32(env, result.error_code.max(0xf9)) };
        }
    } else {
        cb_args[0] = null_value;
        cb_args[1] = unsafe { create_uint32(env, if result.error_code == 0 { 0xf9 } else { result.error_code }) };
    }

    if let Some(napi) = napi() {
        let recv = unsafe { get_undefined(env) };
        let mut call_result = null_mut();
        let status = unsafe { (napi.call_function)(env, recv, js_callback, 2, cb_args.as_ptr(), &mut call_result) };
        log(&format!("ImgJob::deliverToJs callback status={status}"));
    }
}

unsafe extern "C" fn cb_img_job_wire10_async(env: NapiEnv, info: NapiCallbackInfo) -> NapiValue {
    let (args, this_arg) = unsafe { get_args(env, info, 3) };
    if args.len() < 3 {
        return unsafe { get_null(env) };
    }
    let key = match unsafe { value_to_string(env, args[0]) } {
        Ok(v) if !v.is_empty() => v,
        _ => return unsafe { get_null(env) },
    };
    let base_path = args.get(1).copied().and_then(|v| unsafe { value_to_string(env, v).ok() }).unwrap_or_default();
    let callback = args[2];
    if !unsafe { value_is_function(env, callback) } {
        return unsafe { get_null(env) };
    }

    let Some(napi_api) = napi() else {
        return unsafe { get_null(env) };
    };
    let Some(resource_name) = (unsafe { create_string(env, "MzImgJobDeliver") }) else {
        let null_value = unsafe { get_null(env) };
        let cb_args = [null_value, null_value];
        let mut result = null_mut();
        let _ = unsafe { (napi_api.call_function)(env, this_arg, callback, 2, cb_args.as_ptr(), &mut result) };
        return unsafe { get_undefined(env) };
    };

    let mut tsfn = null_mut();
    let status = unsafe { (napi_api.create_threadsafe_function)(env, callback, null_mut(), resource_name, 0x200, 1, null_mut(), null_mut(), null_mut(), Some(img_job_deliver_to_js), &mut tsfn) };
    log(&format!("ImgJob::ensureThreadsafeDelivery create_threadsafe_function status={status} tsfn_is_null={}", tsfn.is_null()));
    if status != NAPI_OK || tsfn.is_null() {
        let null_value = unsafe { get_null(env) };
        let cb_args = [null_value, null_value];
        let mut result = null_mut();
        let _ = unsafe { (napi_api.call_function)(env, this_arg, callback, 2, cb_args.as_ptr(), &mut result) };
        return unsafe { get_undefined(env) };
    }

    let tsfn_addr = tsfn as usize;
    log(&format!("ImgJob::submitAsync key={key} base={base_path}"));
    thread::spawn(move || {
        let outcome = match resource::read_image_resource(&key) {
            Ok(bytes) if !bytes.is_empty() => {
                resource::log(&format!("ImgJob worker ok key={key} bytes={}", bytes.len()));
                ImgJobResult { bytes: Some(bytes), error_code: 0 }
            }
            Ok(_) => {
                resource::log(&format!("ImgJob worker empty key={key}"));
                ImgJobResult { bytes: None, error_code: 0xf9 }
            }
            Err(e) => {
                resource::log(&format!("ImgJob worker failed key={key} code=0x{:02x} error={}", e.code(), e.message()));
                ImgJobResult { bytes: None, error_code: e.code() }
            }
        };
        let payload = Box::into_raw(Box::new(outcome)) as *mut c_void;
        let tsfn = tsfn_addr as NapiThreadsafeFunction;
        if let Some(napi) = napi() {
            let status = unsafe { (napi.call_threadsafe_function)(tsfn, payload, 1) };
            resource::log(&format!("ImgJob::queueDelivery call_threadsafe_function status={status} key={key}"));
            if status != NAPI_OK {
                unsafe {
                    let _ = Box::from_raw(payload as *mut ImgJobResult);
                }
            }
            let release_status = unsafe { (napi.release_threadsafe_function)(tsfn, 0) };
            resource::log(&format!("ImgJob::queueDelivery release_threadsafe_function status={release_status} key={key}"));
        } else {
            unsafe {
                let _ = Box::from_raw(payload as *mut ImgJobResult);
            }
        }
    });

    unsafe { get_undefined(env) }
}

unsafe extern "C" fn cb_is_allowed_fs_write(env: NapiEnv, info: NapiCallbackInfo) -> NapiValue {
    let (args, _) = unsafe { get_args(env, info, 1) };
    let path = args.first().copied().and_then(|v| unsafe { value_to_string(env, v).ok() }).unwrap_or_default();
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
    if status == NAPI_OK && !result.is_null() { result } else { unsafe { create_bool(env, false) } }
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
        export_function(env, exports, c"dispatch", cb_dispatch);
        export_function(env, exports, c"loadVaultJson", cb_load_vault_json);
        export_function(env, exports, c"loadVaultJsonText", cb_load_vault_json_text);
        export_function(env, exports, c"readImageResource", cb_read_image_resource);
        export_function(env, exports, c"scanEnvironment", cb_scan_environment);
        export_function(env, exports, c"isAllowedFsWrite", cb_is_allowed_fs_write);
        export_function(env, exports, c"installWindowHooks", cb_install_window_hooks);
        if let Some(global) = get_global(env) {
            set_named(env, global, c"__mzNative", exports);
            if let Some(dispatch) = get_named(env, exports, c"dispatch") {
                set_named(env, global, c"__mzInvokeVM", dispatch);
            }
        }
    }
}

unsafe fn install_first_script_guard(env: NapiEnv, _exports: NapiValue) {
    log("JsRuntime::installFirstScriptGuard begin");
    let _ = unsafe { run_script_named(env, "JsRuntime::installFirstScriptGuard", INIT_SCRIPT) };
    let _ = unsafe { run_script_named(env, "JsRuntime::installFirstJsonHook", JSON_HOOK_SCRIPT) };
}

unsafe fn install_second_script_guard(env: NapiEnv, exports: NapiValue) -> NapiValue {
    log("JsRuntime::installSecondScriptGuard begin");
    let _ = unsafe { run_script_named(env, "JsRuntime::installSecondScriptGuard", AUTO_HOOK_SCRIPT) };
    exports
}

unsafe fn install_img_job_wire(env: NapiEnv, exports: NapiValue, second_guard_result: NapiValue) {
    log(&format!("Addon::installImgJobWire begin second_guard_result_is_null={}", second_guard_result.is_null()));
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
