use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use argon2::{Algorithm, Argon2, Params, Version};
use flate2::read::DeflateDecoder;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

const RESOURCE_MODE: u32 = 0x77d7f0fc;
const RESOURCE_TOKEN: [u8; 32] = hex32("d3e4e945059199d6078b303ce9f610bac6565a87fc717fb9a70aca91252f7c48");
const JSON_PREVIOUS_TOKEN: [u8; 32] = hex32("2fe931074a0812104f3c8d1c167db2adaaa4523fe54423403dc6e7fdcc39c337");
const SYSTEM_WRAPPER_TOKEN: [u8; 32] = hex32("dd75d68beb7410f13fe71ad5834eb9c774ad8dcd8c04cb504c00fde5bf257245");
const SYSTEM_WRAPPER_NONCE: [u8; 12] = hex12("5b449302abd5c4d4c8183f5f");
const STATIC_SAMPLE16: [u8; 16] = hex16("5ff15008c6483a4d87c70d8b0d0d0e0f");
const STATIC_TOKEN31: [u8; 31] = hex31("4563394e547378314f4c6d46546150447a42567055636463694643674f4576");
const IMAGE_PREVIOUS_TOKEN: [u8; 32] = hex32("d8bcbb62b3338b84e87585e77cfce37dd48ff21a2808767fff8b142043b314a3");
const IMAGE_TOKEN_PREFIX8: [u8; 8] = hex8("943a8cac93b60200");
const RPGMV_HEADER: [u8; 16] = hex16("5250474d560000000003010000000000");
const RPGMV_IMAGE_KEY: [u8; 16] = hex16("bf3b2290e229da2ba272a81c602ea88d");
const JSON_MAC_PREFIX: &[u8] = b"MZ_JSON_V2_ETM";
const JSON_NONCE_PREFIX: &[u8] = b"MZ_JSON_V2_NONCE12";
const IMAGE_EXT_TAG: u64 = 0x474d49364b450000;
const JSON_EXT_TAG: u64 = 0x004a534f4e364b45;

const MODE2_VM_BYTECODE: [u8; 179] = [
    0xb4, 0x0b, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x67, 0xc7, 0x02, 0xe6, 0x01, 0x00, 0x00, 0x00, 0x70, 0x4f, 0xc7,
    0x04, 0xe6, 0x00, 0x00, 0x00, 0x00, 0x70, 0x26, 0xe6, 0x00, 0x00, 0x00, 0x00, 0x80, 0x2f, 0xc7, 0x03, 0x70, 0x1b, 0xc7, 0x04, 0xe6, 0x01, 0x00,
    0x00, 0x00, 0x70, 0x0b, 0xc7, 0x04, 0xe6, 0x02, 0x00, 0x00, 0x00, 0x70, 0x05, 0x14, 0x04, 0x41, 0x14, 0x01, 0xdc, 0x59, 0x14, 0xe0, 0xa1, 0xe6,
    0x00, 0x00, 0x00, 0x00, 0x80, 0x2f, 0xc7, 0x03, 0x70, 0x12, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0xa9, 0x59, 0x14, 0xe9, 0x14, 0x4b, 0xa1, 0xe6, 0x00, 0x00, 0x00, 0x00, 0x80, 0x2f, 0xc7, 0x03, 0x70, 0x10, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0xa9, 0x59, 0x14, 0xeb, 0xc7, 0x04, 0xe6, 0x00, 0x00, 0x00, 0x00, 0x70, 0x26, 0xe6, 0x00, 0x00, 0x00, 0x00,
    0x80, 0x2f, 0xc7, 0x03, 0x70, 0x1b, 0xc7, 0x04, 0xe6, 0x01, 0x00, 0x00, 0x00, 0x70, 0x0b, 0xc7, 0x04, 0xe6, 0x02, 0x00, 0x00, 0x00, 0x70, 0x05,
    0x14, 0x04, 0x41, 0x14, 0x01, 0xdc, 0x59, 0x14, 0xe0, 0x1f, 0xdd,
];

const MODE2_VM_OPCODES: [u8; 179] = hex179(
    "1f241a1a1a1a1a1a1a1a1a1a1a3526ff01ffffffff12ff26ff01ffffffff12ff01ffffffff282726ff12ff26ff01ffffffff12ff26ff01ffffffff12ff1eff321eff33291eff3001ffffffff282726ff12ff1a1a1a1a1a1a1a1a1a1a1a1a1a1a31291eff1eff3001ffffffff282726ff12ff1a1a1a1a1a1a1a1a1a1a1a1a31291eff26ff01ffffffff12ff01ffffffff282726ff12ff26ff01ffffffff12ff26ff01ffffffff12ff1eff321eff33291eff3400",
);

static STATE: OnceLock<Mutex<ResourceState>> = OnceLock::new();

struct ResourceState {
    root_dir: PathBuf,
    containers: HashMap<PathBuf, LoadedContainer>,
    json_cache: HashMap<String, String>,
    dynamic_prefix: Option<[u8; 0x74]>,
}

struct LoadedContainer {
    data: Vec<u8>,
    index: Vec<u8>,
    container: ContainerInfo,
}

#[derive(Clone, Copy)]
struct ContainerInfo {
    index_key: u32,
    index_size: usize,
    record_count: usize,
    flags: u32,
    effective_size: usize,
    data_base: usize,
}

#[derive(Clone)]
struct Record {
    extended: bool,
    payload_offset: usize,
    payload_length: usize,
    flags: u32,
    key_a: [u8; 16],
    mac_key_input: [u8; 32],
    mac: [u8; 16],
}

#[derive(Deserialize)]
struct Wrapper {
    v: u32,
    u: String,
    #[serde(default)]
    t: String,
    d: String,
    a: String,
}

struct Mode2Ctx {
    p34: u32,
    p38: u32,
    p30: u32,
    p58: u32,
    p54: u32,
    p44: u32,
    p4c: u32,
    p50: u32,
    delim: u8,
    p3c: u32,
    p40: u32,
}

pub fn init_root() -> PathBuf {
    let root = detect_root_dir();
    let _ = STATE.set(Mutex::new(ResourceState {
        root_dir: root.clone(),
        containers: HashMap::new(),
        json_cache: HashMap::new(),
        dynamic_prefix: None,
    }));
    root
}

pub fn root_dir() -> PathBuf {
    state().lock().map(|s| s.root_dir.clone()).unwrap_or_else(|_| detect_root_dir())
}

pub fn load_vault_json_text(input: &str) -> Result<String, String> {
    let norm_key = json_vault_key(input);
    log(&format!("loadVaultJson begin key={norm_key}"));
    {
        let guard = state().lock().map_err(|_| "resource mutex poisoned".to_string())?;
        if let Some(cached) = guard.json_cache.get(&norm_key) {
            return Ok(cached.clone());
        }
    }
    let decode_mode = fnv1a32(&norm_key, true);
    let hash = fnv1a64_normalized(&norm_key);
    let payload = read_container_resource(Path::new("data").join("json.dat"), &norm_key, decode_mode, hash)?
        .ok_or_else(|| format!("missing JSON vault record: {norm_key}"))?;
    let wrapper = extract_wrapper(&payload)?;
    let (token, nonce) = wrapper_token_for(&norm_key, &wrapper, decode_mode)?;
    let mac = verify_wrapper_mac(&wrapper, &token, &nonce)?;
    if !mac.eq_ignore_ascii_case(&wrapper.a) {
        return Err(format!("JSON wrapper MAC failed for {norm_key}; dynamic token stage is not closed"));
    }
    let plain = decode_mode_2d(&wrapper, &token)?;
    let text = String::from_utf8(plain).map_err(|e| format!("json utf8 failed: {e}"))?;
    serde_json::from_str::<serde_json::Value>(&text).map_err(|e| format!("json parse failed: {e}"))?;
    {
        let mut guard = state().lock().map_err(|_| "resource mutex poisoned".to_string())?;
        guard.json_cache.insert(norm_key.clone(), text.clone());
    }
    log(&format!("loadVaultJson ok key={norm_key} bytes={}", text.len()));
    Ok(text)
}

pub fn read_image_resource(input: &str) -> Result<Option<Vec<u8>>, String> {
    let p = normalize_url_path(input).trim_end_matches('_').to_string();
    let direct = [p.clone(), format!("{p}_")];
    let root = root_dir();
    for rel in direct {
        let full = root.join(&rel);
        if full.is_file() {
            return fs::read(&full)
                .map(Some)
                .map_err(|e| format!("read image file {} failed: {e}", full.display()));
        }
    }
    let containers = resolve_dat_containers_for_image(&p);
    if containers.is_empty() {
        return Ok(None);
    }
    let internal_key = normalize_image_resource_key(&p);
    let decode_mode = fnv1a32(&internal_key, false);
    let hash = fnv1a64_normalized(&internal_key);
    for container in containers {
        if let Some(payload) = read_container_resource(container, &internal_key, decode_mode, hash)? {
            return decode_image_payload_for_xhr(payload).map(Some);
        }
    }
    Ok(None)
}

pub fn is_allowed_fs_write(target: &str) -> bool {
    let root = root_dir();
    let full = root.join(target);
    let full_s = full.to_string_lossy().replace('/', "\\").to_lowercase();
    let root_s = root.to_string_lossy().replace('/', "\\").to_lowercase();
    let base = full.file_name().and_then(|v| v.to_str()).unwrap_or("").to_lowercase();
    full_s.contains("\\save\\")
        || matches!(base.as_str(), "package.json" | "c" | "mz_rust.log")
        || (full_s.starts_with(&(root_s + "\\data\\")) && base.ends_with(".rmmzsave"))
}

pub fn log(message: &str) {
    let root = detect_root_dir();
    let line = format!("[mz-rust-resource] {message}\r\n");
    let _ = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(root.join("mz_rust.log"))
        .and_then(|mut f| std::io::Write::write_all(&mut f, line.as_bytes()));
}

fn state() -> &'static Mutex<ResourceState> {
    STATE.get_or_init(|| {
        Mutex::new(ResourceState {
            root_dir: detect_root_dir(),
            containers: HashMap::new(),
            json_cache: HashMap::new(),
            dynamic_prefix: None,
        })
    })
}

fn detect_root_dir() -> PathBuf {
    if let Ok(cwd) = std::env::current_dir() {
        if cwd.join("data").join("json.dat").is_file() {
            return cwd;
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let root = if dir
                .file_name()
                .and_then(|s| s.to_str())
                .map(|s| s.eq_ignore_ascii_case("js"))
                .unwrap_or(false)
            {
                dir.parent().unwrap_or(dir).to_path_buf()
            } else {
                dir.to_path_buf()
            };
            if root.join("data").join("json.dat").is_file() {
                return root;
            }
        }
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn normalize_url_path(input: &str) -> String {
    let mut p = input.split('?').next().unwrap_or("").split('#').next().unwrap_or("").replace('\\', "/");
    p = percent_decode_best_effort(&p);
    let mut out: Vec<&str> = Vec::new();
    for part in p.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            out.pop();
        } else {
            out.push(part);
        }
    }
    out.join("/")
}

fn percent_decode_best_effort(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(a), Some(b)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((a << 4) | b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| input.to_string())
}

fn json_vault_key(input: &str) -> String {
    let p = normalize_url_path(input);
    let l = p.to_lowercase();
    if let Some(i) = l.find("dataex/") {
        return p[i..].to_string();
    }
    if let Some(i) = l.find("data/") {
        return p[i + 5..].to_string();
    }
    p.rsplit('/').next().unwrap_or(&p).to_string()
}

fn normalize_image_resource_key(input: &str) -> String {
    let mut p = normalize_url_path(input).trim_end_matches('_').to_string();
    if p.to_lowercase().starts_with("img/") {
        p = p[4..].to_string();
    }
    p = p.to_lowercase();
    if p.ends_with(".png") {
        p.push('_');
    }
    p
}

fn canonical_for_decode_mode(input: &str, keep_case_for_data: bool) -> String {
    let mut p = input.trim_start().replace('\\', "/");
    while p.ends_with('/') || p.ends_with(' ') {
        p.pop();
    }
    if p.starts_with("./") {
        p = p[2..].to_string();
    }
    if p.to_lowercase().starts_with("data/") {
        p = p[5..].to_string();
    }
    if !keep_case_for_data {
        p = p.to_lowercase();
    }
    p
}

fn fnv1a32(input: &str, keep_case_for_data: bool) -> u32 {
    let s = canonical_for_decode_mode(input, keep_case_for_data);
    let mut h = 0x811c9dc5u32;
    for b in s.bytes() {
        h = h.wrapping_shl(0) ^ b as u32;
        h = h.wrapping_mul(0x01000193);
    }
    h
}

fn fnv1a64_normalized(input: &str) -> u64 {
    let s = canonical_for_decode_mode(input, true);
    let mut h = 0xcbf29ce484222325u64;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn parse_container(file: &[u8]) -> Result<ContainerInfo, String> {
    if file.len() < 0x30 {
        return Err("truncated resource container header".to_string());
    }
    let header = decrypt_header(file)?;
    if &header[0..4] != [0x34, 0xd3, 0x1c, 0xf7] {
        return Err("bad resource container magic".to_string());
    }
    if read_u32_le(&header, 4)? != 2 {
        return Err("bad resource container version".to_string());
    }
    if read_u32_le(&header, 8)? != RESOURCE_MODE {
        return Err("bad resource container mode".to_string());
    }
    let index_key = read_u32_le(&header, 12)?;
    let index_size = read_u32_le(&header, 16)? as usize;
    let flags = read_u32_le(&header, 28)?;
    let tail_size = read_u32_le(&header, 32)? as usize;
    let mut effective_size = file.len();
    if (flags & 0x20) != 0 && tail_size != 0 && effective_size > tail_size {
        effective_size -= tail_size;
    }
    if effective_size < 0x30 + index_size {
        return Err("truncated resource container".to_string());
    }
    Ok(ContainerInfo {
        index_key,
        index_size,
        record_count: index_key as usize,
        flags,
        effective_size,
        data_base: 0x30 + index_size,
    })
}

fn decrypt_header(file: &[u8]) -> Result<[u8; 0x30], String> {
    let mut s = seed_from_token32(RESOURCE_MODE, &RESOURCE_TOKEN);
    let mut out = [0u8; 0x30];
    let mut shift = 0u32;
    for i in 0..0x30 {
        s = s.wrapping_mul(0x19660d).wrapping_add(RESOURCE_MODE).wrapping_add(0x3c6ef35f);
        out[i] = *file.get(i).ok_or_else(|| "truncated resource header".to_string())? ^ ((s >> (shift & 0x18)) & 0xff) as u8;
        shift = shift.wrapping_add(8);
    }
    Ok(out)
}

fn seed_from_token32(mode: u32, token: &[u8; 32]) -> u32 {
    let mut seed = mode.wrapping_mul(0x9e3779b1) ^ 0x1445f3fd;
    for (i, b) in token.iter().enumerate() {
        seed = (seed ^ ((*b as u32) << ((i * 8) & 0x18))).wrapping_mul(0x9e3779b1);
    }
    seed
}

fn load_container(rel: PathBuf) -> Result<(), String> {
    let full = {
        let guard = state().lock().map_err(|_| "resource mutex poisoned".to_string())?;
        guard.root_dir.join(rel)
    };
    {
        let guard = state().lock().map_err(|_| "resource mutex poisoned".to_string())?;
        if guard.containers.contains_key(&full) {
            return Ok(());
        }
    }
    let file = fs::read(&full).map_err(|e| format!("read container {} failed: {e}", full.display()))?;
    let container = parse_container(&file)?;
    let mut index = file[0x30..0x30 + container.index_size].to_vec();
    if (container.flags & 8) != 0 {
        let (a, b) = derive_transform_key_pair(0xf8109c987e1c0e55, RESOURCE_MODE, &RESOURCE_TOKEN);
        transform_buffer(&mut index, a, b);
    } else {
        for (i, v) in index.iter_mut().enumerate() {
            *v ^= RESOURCE_TOKEN[i & 0x1f];
        }
    }
    if read_u32_le(&index, 0)? < 1 || read_u32_le(&index, 0)? > 2 || read_u32_le(&index, 4)? != container.index_key {
        return Err("bad resource index".to_string());
    }
    let mut data = file[container.data_base..container.effective_size].to_vec();
    if (container.flags & 0x50) == 0x10 {
        let (a, b) = derive_transform_key_pair(0xe59a55f5c0b8c8a2, RESOURCE_MODE, &RESOURCE_TOKEN);
        transform_buffer(&mut data, a, b);
    }
    {
        let mut guard = state().lock().map_err(|_| "resource mutex poisoned".to_string())?;
        maybe_install_dynamic_prefix(&mut guard, &index, container)?;
        guard.containers.insert(full, LoadedContainer { data, index, container });
    }
    Ok(())
}

fn read_container_resource(rel: PathBuf, _key: &str, decode_mode: u32, hash: u64) -> Result<Option<Vec<u8>>, String> {
    load_container(rel.clone())?;
    let full = {
        let guard = state().lock().map_err(|_| "resource mutex poisoned".to_string())?;
        guard.root_dir.join(rel)
    };
    let guard = state().lock().map_err(|_| "resource mutex poisoned".to_string())?;
    let loaded = guard.containers.get(&full).ok_or_else(|| "container cache missing".to_string())?;
    let Some(record) = find_record(&loaded.index, loaded.container.record_count, hash)? else {
        return Ok(None);
    };
    decode_record_payload(loaded, &record, hash, decode_mode).map(Some)
}

fn maybe_install_dynamic_prefix(state: &mut ResourceState, index: &[u8], container: ContainerInfo) -> Result<(), String> {
    if (container.flags & 0x200) == 0 || state.dynamic_prefix.is_some() {
        return Ok(());
    }
    let typ = read_u32_le(index, 0)?;
    let stride = if typ == 2 { 0x58 } else { 0x18 };
    let table_off = 8 + stride * container.record_count;
    let table_len = (container.record_count << 4) + 0x14;
    if table_off + table_len + 16 > index.len() {
        return Ok(());
    }
    if read_u32_le(index, table_off)? != 0x4554534d
        || read_u32_le(index, table_off + 4)? != 1
        || read_u32_le(index, table_off + 8)? != 0x74
        || read_u32_le(index, table_off + 0x0c)? != 0x10
    {
        return Ok(());
    }
    let block = &index[table_off..table_off + table_len];
    let expected = &index[table_off + table_len..table_off + table_len + 16];
    let key = dynamic_prefix_seed_key(&RESOURCE_TOKEN, RESOURCE_MODE);
    let actual = hmac_sha256(&key, block);
    if actual[..16] != expected[..] && std::env::var("MZ_STRICT_MSTE").ok().as_deref() == Some("1") {
        return Ok(());
    }
    let mut out = [0u8; 0x74];
    for (i, v) in out.iter_mut().enumerate() {
        let lane = i & 0x0f;
        let page = i & 0x70;
        *v = block[0x14 + page + lane] ^ key[lane] ^ (((lane << 5).wrapping_sub(lane)) & 0xff) as u8;
    }
    state.dynamic_prefix = Some(out);
    Ok(())
}

fn find_record(index: &[u8], record_count: usize, hash: u64) -> Result<Option<Record>, String> {
    let typ = read_u32_le(index, 0)?;
    let stride = if typ == 2 { 0x58 } else { 0x18 };
    let mut off = 8usize;
    for _ in 0..record_count {
        if off + stride > index.len() {
            return Ok(None);
        }
        let h = read_u64_le(index, off)?;
        if h == hash {
            let mut key_a = [0u8; 16];
            let mut mac_key_input = [0u8; 32];
            let mut mac = [0u8; 16];
            if typ == 2 {
                key_a.copy_from_slice(&index[off + 0x18..off + 0x28]);
                mac_key_input.copy_from_slice(&index[off + 0x28..off + 0x48]);
                mac.copy_from_slice(&index[off + 0x48..off + 0x58]);
            }
            return Ok(Some(Record {
                extended: typ == 2,
                payload_offset: read_u64_le(index, off + 8)? as usize,
                payload_length: read_u32_le(index, off + 0x10)? as usize,
                flags: read_u32_le(index, off + 0x14)?,
                key_a,
                mac_key_input,
                mac,
            }));
        }
        if h > hash {
            break;
        }
        off += stride;
    }
    Ok(None)
}

fn decode_record_payload(loaded: &LoadedContainer, record: &Record, path_hash: u64, decode_mode: u32) -> Result<Vec<u8>, String> {
    if record.payload_length > loaded.container.effective_size
        || record.payload_offset > loaded.container.effective_size.saturating_sub(record.payload_length)
    {
        return Err("record payload out of range".to_string());
    }
    let start = record.payload_offset;
    let end = start + record.payload_length;
    if end > loaded.data.len() {
        return Err("record payload out of decoded data range".to_string());
    }
    let mut payload = loaded.data[start..end].to_vec();
    if record.extended {
        let is_json = (record.flags & 1) != 0;
        let derived_key = derive_extended_record_key(record, is_json, path_hash, decode_mode, loaded.container.flags & 0xff)?;
        let (ok, tmp_key) = verify_extended_record_mac(record, &derived_key);
        if !ok {
            return Err("extended record MAC failed".to_string());
        }
        if (record.flags & 4) != 0 {
            let (a, b) = derive_transform_key_pair(path_hash, RESOURCE_MODE, &tmp_key);
            transform_buffer(&mut payload, a, b);
        }
    }
    Ok(payload)
}

fn derive_extended_record_key(record: &Record, is_json: bool, hash: u64, caller_int: u32, container_flags: u32) -> Result<[u8; 32], String> {
    let mut material = Vec::with_capacity(STATIC_TOKEN31.len() + 0x30);
    material.extend_from_slice(&STATIC_TOKEN31);
    material.extend_from_slice(&0x21fc1au32.to_le_bytes());
    material.extend_from_slice(&RESOURCE_MODE.to_le_bytes());
    material.extend_from_slice(&3u32.to_le_bytes());
    material.extend_from_slice(&(if is_json { JSON_EXT_TAG } else { IMAGE_EXT_TAG }).to_le_bytes());
    material.extend_from_slice(&hash.to_le_bytes());
    material.extend_from_slice(&record.key_a);
    material.extend_from_slice(&caller_int.to_le_bytes());
    if (container_flags & 0x80) != 0 {
        let params = Params::new(0x18000, 1, 8, Some(0x20)).map_err(|e| format!("argon2 params failed: {e}"))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = [0u8; 32];
        argon2
            .hash_password_into(&material, &record.key_a, &mut out)
            .map_err(|e| format!("argon2id failed: {e}"))?;
        Ok(out)
    } else {
        Ok(sha256(&material))
    }
}

fn verify_extended_record_mac(record: &Record, derived_key: &[u8; 32]) -> (bool, [u8; 32]) {
    let (a, b) = derive_transform_key_pair(0xe6e6e6e6e6e6e6e6, 0, derived_key);
    let mut tmp = record.mac_key_input;
    transform_buffer(&mut tmp, a, b);
    let mac = hmac_sha256(derived_key, &tmp);
    (mac[..16] == record.mac[..], tmp)
}

fn extract_wrapper(payload: &[u8]) -> Result<Wrapper, String> {
    if payload.first() == Some(&b'{') {
        return serde_json::from_slice(payload).map_err(|e| format!("json wrapper parse failed: {e}"));
    }
    if payload.len() >= 0x111 && payload[0] == b'[' && payload[0x110] == b'{' {
        return serde_json::from_slice(&payload[0x110..]).map_err(|e| format!("json wrapper parse failed: {e}"));
    }
    Err("unknown JSON wrapper payload".to_string())
}

fn wrapper_token_for(key: &str, wrapper: &Wrapper, decode_mode: u32) -> Result<([u8; 32], [u8; 12]), String> {
    if key.eq_ignore_ascii_case("System.json") {
        return Ok((SYSTEM_WRAPPER_TOKEN, SYSTEM_WRAPPER_NONCE));
    }
    let token = derive_json_wrapper_token_static(wrapper, decode_mode)?;
    let nonce = derive_nonce12(&token, &wrapper.u);
    Ok((token, nonce))
}

fn derive_json_wrapper_token_static(wrapper: &Wrapper, decode_mode: u32) -> Result<[u8; 32], String> {
    let u = parse_hex_u32(&wrapper.u);
    let mut msg = [0u8; 0x25];
    let prefix = {
        let guard = state().lock().map_err(|_| "resource mutex poisoned".to_string())?;
        if let Some(dynamic) = guard.dynamic_prefix {
            dynamic[0..8].try_into().unwrap()
        } else {
            [0u8; 8]
        }
    };
    msg[0..8].copy_from_slice(&prefix);
    msg[8..12].copy_from_slice(&u.to_le_bytes());
    msg[12..16].copy_from_slice(&u.to_le_bytes());
    msg[16..20].copy_from_slice(&decode_mode.to_le_bytes());
    msg[20..36].copy_from_slice(&STATIC_SAMPLE16);
    msg[0x24] = 1;
    Ok(hmac_sha256(&JSON_PREVIOUS_TOKEN, &msg))
}

fn derive_nonce12(token: &[u8; 32], u: &str) -> [u8; 12] {
    if u.as_bytes().len() != 8 {
        return [0u8; 12];
    }
    let mut msg = Vec::with_capacity(JSON_NONCE_PREFIX.len() + 8);
    msg.extend_from_slice(JSON_NONCE_PREFIX);
    msg.extend_from_slice(u.as_bytes());
    let h = hmac_sha256(token, &msg);
    h[0..12].try_into().unwrap()
}

fn verify_wrapper_mac(wrapper: &Wrapper, token: &[u8; 32], nonce: &[u8; 12]) -> Result<String, String> {
    let mut normalized_t = wrapper.t.as_bytes().to_vec();
    for b in &mut normalized_t {
        if (b'a'..b'g').contains(b) {
            *b -= 0x20;
        }
    }
    let mut msg = Vec::new();
    msg.extend_from_slice(JSON_MAC_PREFIX);
    msg.extend_from_slice(&wrapper.v.to_le_bytes());
    msg.extend_from_slice(nonce);
    msg.extend_from_slice(wrapper.u.as_bytes());
    msg.extend_from_slice(&normalized_t);
    msg.extend_from_slice(&(wrapper.d.len() as u64).to_le_bytes());
    msg.extend_from_slice(wrapper.d.as_bytes());
    let mac = hmac_sha256(token, &msg);
    Ok(to_hex_lower(&mac[..16]))
}

fn decode_image_payload_for_xhr(payload: Vec<u8>) -> Result<Vec<u8>, String> {
    if payload.len() < RPGMV_HEADER.len() || payload[0..RPGMV_HEADER.len()] != RPGMV_HEADER {
        return Ok(payload);
    }
    let mut body = payload[RPGMV_HEADER.len()..].to_vec();
    if body.len() < RPGMV_IMAGE_KEY.len() {
        return Err("truncated RPGMV image body".to_string());
    }
    for i in 0..RPGMV_IMAGE_KEY.len() {
        body[i] ^= RPGMV_IMAGE_KEY[i];
    }
    decode_native_image_tail(&mut body)?;
    wrap_rpgmv_image_for_xhr(body)
}

fn wrap_rpgmv_image_for_xhr(mut body: Vec<u8>) -> Result<Vec<u8>, String> {
    if body.len() < RPGMV_IMAGE_KEY.len() {
        return Err("truncated decoded image body".to_string());
    }
    for i in 0..RPGMV_IMAGE_KEY.len() {
        body[i] ^= RPGMV_IMAGE_KEY[i];
    }
    let mut out = Vec::with_capacity(RPGMV_HEADER.len() + body.len());
    out.extend_from_slice(&RPGMV_HEADER);
    out.extend_from_slice(&body);
    Ok(out)
}

fn decode_native_image_tail(buf: &mut Vec<u8>) -> Result<(), String> {
    if buf.len() < 4 {
        return Err("native image payload too small".to_string());
    }
    let len = buf.len();
    let len4 = len - 4;
    if len4 < 0x111 {
        buf.truncate(len4);
        return Ok(());
    }
    let tail_seed = read_u32_le(buf, len4)?;
    let hash = rolling_image_hash(buf);
    let token = derive_image_decode_token(hash, tail_seed, len4 as u32);
    apply_native_image_transform(buf, len4, hash, &token);
    buf.truncate(len4);
    Ok(())
}

fn rolling_image_hash(buf: &[u8]) -> u32 {
    let mut h = 0u32;
    for b in buf.iter().take(0x110) {
        h = h.wrapping_mul(0x1f).wrapping_add(*b as u32);
    }
    h
}

fn derive_image_decode_token(hash: u32, tail_seed: u32, len4: u32) -> [u8; 32] {
    let mut msg = Vec::with_capacity(0x25);
    msg.extend_from_slice(&IMAGE_TOKEN_PREFIX8);
    msg.extend_from_slice(&hash.to_le_bytes());
    msg.extend_from_slice(&tail_seed.to_le_bytes());
    msg.extend_from_slice(&len4.to_le_bytes());
    msg.extend_from_slice(&STATIC_SAMPLE16);
    msg.push(1);
    hmac_sha256(&IMAGE_PREVIOUS_TOKEN, &msg)
}

fn apply_native_image_transform(buf: &mut [u8], len4: usize, hash: u32, token: &[u8; 32]) {
    let state1 = hash_token32_b(token);
    let state2 = hash;
    let hash_a = hash_token32_a(token);
    let seed = hash_a ^ hash ^ state1.wrapping_mul(0x04b22496) ^ 0x391195b2;
    let mut state0 = read_u32_le(token, 0).unwrap()
        ^ read_u32_le(token, 4).unwrap()
        ^ read_u32_le(token, 8).unwrap()
        ^ read_u32_le(token, 12).unwrap()
        ^ seed
        ^ 0x38455f1a;
    for i in 0..(len4 - 0x110) {
        state0 = state0.wrapping_mul(0x13ff3d2a).wrapping_add(0x000b971a) ^ (state2 >> 5) ^ state1;
        let lane = (((i as u32 & 0x1f) ^ 0x10).wrapping_add(0xb9) & 0xff) as u8;
        let mask = lane ^ ((state0 >> 8) as u8) ^ (state0 as u8) ^ 0x12;
        buf[0x110 + i] ^= mask;
    }
}

fn decode_mode_2d(wrapper: &Wrapper, token: &[u8; 32]) -> Result<Vec<u8>, String> {
    let mut ctx = derive_ctx(wrapper, token);
    let delim = ctx.delim as char;
    let mut blocks: Vec<String> = wrapper.d.split(delim).map(|s| s.to_string()).collect();
    if blocks.len() >= 3 && ctx.p54 != 0 {
        blocks = reorder_blocks(blocks, (ctx.p50 ^ ctx.p58) & 0xff, 5, 1, 7, 0x0b);
    }
    if blocks.len() >= 2 && ((ctx.p38 ^ ctx.p30) & 1) == 1 {
        blocks = reorder_blocks(blocks, ctx.p58 & 0xff, 1, 0, 3, 0x11);
    }
    let modulus = if ctx.p4c == 0 { 3 } else { ctx.p4c };
    for (i, block) in blocks.iter_mut().enumerate() {
        if ((ctx.p58 + i as u32) % modulus) == 1 {
            *block = block.chars().rev().collect();
        }
    }
    let joined = blocks.join("");
    let mut buf = hex_decode(joined.as_bytes())?;
    compute_params(&mut ctx);
    apply_mode2_vm_transforms(&mut buf, &ctx, token)?;
    inflate_raw(&buf)
}

fn derive_ctx(wrapper: &Wrapper, token: &[u8; 32]) -> Mode2Ctx {
    let p30 = parse_hex_u32(&wrapper.u);
    let p38 = hash_token32_b(token);
    let q = p30 ^ 0x21fc1a;
    let idx = (q as u64).wrapping_sub((((q as u64) * 0xcccccccd) >> 34) * 5) as u32;
    let chars = b"-_:~|";
    Mode2Ctx {
        p34: hash_token32_a(token),
        p38,
        p30,
        p58: if wrapper.u.len() >= 2 { parse_hex_u32(&wrapper.u[0..2]) } else { 0 },
        p54: 1,
        p44: (p30 & 3) ^ 1,
        p4c: 2,
        p50: (p30 & 0xff) ^ (p38 & 0xff) ^ 0xf6,
        delim: chars[(idx as usize) & 0xffffffffusize],
        p3c: 0,
        p40: 0,
    }
}

fn reorder_blocks(blocks: Vec<String>, seed: u32, a: u32, b: u32, c: u32, d: u32) -> Vec<String> {
    let count = blocks.len() as u32;
    let mut step = (((a.wrapping_mul(seed).wrapping_add(b)) | 1) % count).max(1);
    loop {
        let g = gcd_for_native_step(step as i32, count as i32) as u32;
        if ((g + 1) & 0xfffffffd) == 0 {
            break;
        }
        step = (step + 2) % count;
        if step == 0 {
            step = 1;
        }
    }
    let mut pos = c.wrapping_mul(seed).wrapping_add(d) % count;
    let mut out = Vec::with_capacity(blocks.len());
    for _ in 0..count {
        out.push(blocks[(pos % count) as usize].clone());
        pos = pos.wrapping_add(step);
    }
    out
}

fn gcd_for_native_step(mut cur: i32, mut den: i32) -> i32 {
    loop {
        let rem = cur % den;
        if rem == 0 {
            return den;
        }
        cur = den;
        den = rem;
    }
}

fn compute_params(ctx: &mut Mode2Ctx) {
    let r14 = ctx.p30;
    let mut r10 = ctx.p34;
    let mut rcx = 0x10u32;
    let (rdx, r8, r11, rsi, rbx, rdi, rbp): (u32, u32, u32, u32, u32, u32, u32);
    match ctx.p44 & 3 {
        0 => {
            r11 = 0x846ca68b;
            rdx = 0x0f;
            rsi = 0x7feb352d;
            rbx = 0x4685fce1;
            rdi = 0x9e3779b9;
            rbp = r14;
            r8 = 0x10;
        }
        1 => {
            r11 = 0xc2b2ae35;
            rdx = 0x0d;
            rsi = 0x85ebca87;
            rbx = 0x8d69fdec;
            rdi = 0x27d4eb2d;
            rbp = r14;
            r8 = 0x10;
        }
        2 => {
            r8 = 0x0d;
            r11 = 0x846ca68b;
            rdx = 0x10;
            rsi = 0x7feb352d;
            rcx = 0x0f;
            rbx = 0x4685fce1;
            rdi = 0xb5297a4d;
            rbp = r14.rotate_left(1);
        }
        _ => {
            rdx = 0x0f;
            rsi = 0x6ed9eba1;
            rbx = 0x55f39b24;
            rdi = 0x9e3779b9;
            rbp = r10.wrapping_add(0x21fc1a);
            r10 = r14;
            r11 = 0x9e3779b9;
            r8 = 0x10;
        }
    }
    let mut x = rdi.wrapping_mul(ctx.p38) ^ rbp ^ r10 ^ rbx;
    x = ((x >> rcx) ^ x).wrapping_mul(rsi);
    x = ((x >> rdx) ^ x).wrapping_mul(r11);
    x = (x >> r8) ^ x;
    let mut c = (x >> 5) & 0xff;
    if c == 0 {
        let v = x >> 13;
        c = (v as u64).wrapping_sub((((v as u64) * 0x1010102) >> 32) * 0xff).wrapping_add(1) as u32;
    }
    let v = x >> 3;
    let mod3 = (v as u64).wrapping_sub((((v as u64) * 0x55555556) >> 32) * 3) as u32;
    ctx.p3c = ((c << 8).wrapping_add(mod3 << 3)) | (x % 3) | (x & 4);
    ctx.p40 = (x >> 2) & 1;
}

fn apply_mode2_vm_transforms(buf: &mut [u8], ctx: &Mode2Ctx, token: &[u8; 32]) -> Result<(), String> {
    let slots = [ctx.p30, ctx.p3c, ctx.p40, buf.len() as u32, ctx.p3c & 3];
    let mut stack: Vec<u32> = Vec::new();
    let mut loop_index = 0u32;
    let mut pc = 0usize;
    let mut f6f9_state: Option<([u32; 8], u8)> = None;
    let mut guard = 0usize;
    let guard_limit = std::cmp::max(1_000_000, buf.len() * 64 + 4096);
    while pc < MODE2_VM_BYTECODE.len() && guard < guard_limit {
        guard += 1;
        let raw = MODE2_VM_BYTECODE[pc];
        let op = MODE2_VM_OPCODES[pc];
        pc += 1;
        match op {
            0x00 => return Ok(()),
            0x1a | 0x35 => {}
            0x26 => {
                let idx = (MODE2_VM_BYTECODE[pc] & 0x0f) as usize;
                pc += 1;
                stack.push(slots[idx]);
            }
            0x01 => {
                let v = read_u32_le(&MODE2_VM_BYTECODE, pc)?;
                pc += 4;
                stack.push(v);
            }
            0x12 => {
                let off = MODE2_VM_BYTECODE[pc] as i8;
                pc += 1;
                let a = stack.pop().ok_or_else(|| "mode2 vm stack underflow".to_string())?;
                let b = stack.pop().ok_or_else(|| "mode2 vm stack underflow".to_string())?;
                if a == b {
                    pc = ((pc as isize) + off as isize) as usize;
                }
            }
            0x28 => loop_index = stack.pop().ok_or_else(|| "mode2 vm stack underflow".to_string())?,
            0x27 => stack.push(loop_index),
            0x29 => loop_index = loop_index.wrapping_add(1),
            0x1e => {
                let off = MODE2_VM_BYTECODE[pc] as i8;
                pc = ((pc + 1) as isize + off as isize) as usize;
            }
            0x1f => pc += 1,
            0x32 => f7fb_xor_byte(buf, loop_index as usize, ctx.p30 as u8, token),
            0x30 => f6f9_state = Some(init_f6f9_state(ctx, buf.len(), token)),
            0x31 => {
                if f6f9_state.is_none() {
                    f6f9_state = Some(init_f6f9_state(ctx, buf.len(), token));
                }
                if let Some((state, byte19)) = f6f9_state.as_mut() {
                    let idx = buf.len() - 1 - loop_index as usize;
                    f6f9_stream_byte(state, *byte19, buf, idx);
                }
            }
            0x33 => f6c6_ror_xor_byte(buf, loop_index as usize, ctx.p30 as u8, token),
            0x34 => return Ok(()),
            _ => return Err(format!("unknown mode2 opcode 0x{op:x} raw=0x{raw:x}")),
        }
    }
    Err("mode2 VM guard exceeded".to_string())
}

fn init_f6f9_state(ctx: &Mode2Ctx, len: usize, token: &[u8; 32]) -> ([u32; 8], u8) {
    let mut state = [0u32; 8];
    state[7] = len as u32;
    state[3] = ctx.p30;
    state[4] = (ctx.p3c >> 3) & 3;
    state[5] = (ctx.p3c >> 8) & 0xff;
    state[1] = hash_token32_a(token);
    state[2] = hash_token32_b(token);
    let seed = ctx.p30 ^ state[1] ^ state[2].wrapping_mul(0x5b02f25f) ^ 0xfaf6f2a3;
    state[0] = read_u32_le(token, 0).unwrap()
        ^ read_u32_le(token, 4).unwrap()
        ^ read_u32_le(token, 8).unwrap()
        ^ read_u32_le(token, 12).unwrap()
        ^ seed
        ^ 0x4ea92ee7;
    state[6] = ctx.p30 & 0xff;
    let byte19 = (((ctx.p30 >> 16) & 0xff) ^ (ctx.p30 & 0xff) ^ (state[1] & 0xff) ^ (state[2] & 0xff)) as u8;
    (state, byte19)
}

fn f6f9_stream_byte(state: &mut [u32; 8], byte19: u8, buf: &mut [u8], idx: usize) {
    if state[7] == 0 {
        return;
    }
    let key_b = state[2];
    let mode = state[4];
    let mixed_index = key_b ^ idx as u32;
    let x = ((state[3] >> 16) & 0xffff) ^ mixed_index ^ state[0].wrapping_mul(0x0805e63e).wrapping_add(0x117a1d);
    state[0] = x;
    let prev = (state[6] & 0xff) as u8;
    let mut k = if mode == 1 {
        let v = key_b.wrapping_add(idx as u32);
        let q = (((v as u64) * 0x0ab8f69e3) >> 39) as u32;
        let a = v.wrapping_sub(q.wrapping_mul(0xbf)) as u8;
        let r = (((prev >> 4) | (prev << 3)) & 0xff) as u8;
        (((a ^ byte19.wrapping_add(0x46)).wrapping_add(r)) ^ 0x9c).wrapping_add(0x13)
    } else if mode != 0 {
        (((((prev >> 3) ^ prev).wrapping_add((mixed_index % 0x71) as u8)).wrapping_add(byte19 ^ 0x46)) ^ 0x9c).wrapping_add(0x13)
    } else {
        ((x >> 16) as u8) ^ (x as u8) ^ 0xda
    };
    k = (k ^ buf[idx] ^ (((idx & 0x0f) as u8).wrapping_add(state[5] as u8))) & 0xff;
    buf[idx] = prev ^ k;
    state[6] = k as u32;
}

fn f6c6_ror_xor_byte(buf: &mut [u8], idx: usize, salt: u8, token: &[u8; 32]) {
    let key = ((idx as u32).wrapping_mul(3).wrapping_add(salt as u32).wrapping_add(hash_token32_b(token)) & 0xff) as u8;
    buf[idx] = buf[idx].rotate_right(1) ^ key;
}

fn f7fb_xor_byte(buf: &mut [u8], idx: usize, salt: u8, token: &[u8; 32]) {
    let key = ((idx as u32).wrapping_add(salt as u32).wrapping_add(hash_token32_b(token)) & 0xff) as u8;
    buf[idx] ^= key;
}

fn transform_buffer(buf: &mut [u8], key_a: u64, key_b: u64) {
    for (i, v) in buf.iter_mut().enumerate() {
        let r = prf64_at(key_a, key_b, i as u64);
        let mask = ((r & 0xff) ^ ((r >> 32) & 0xff) ^ ((r >> 48) & 0xff)) as u8;
        let sub = ((r >> 17) % 251) as u8;
        *v = (*v ^ mask).wrapping_sub(sub);
    }
}

fn prf64_at(key_a: u64, key_b: u64, i: u64) -> u64 {
    let v8 = neg64(0x29170143ff82e97f)
        .wrapping_sub(i.wrapping_mul(0x29170143ff82e97f))
        .wrapping_add(key_b.rotate_left(((i * 13 + 7) % 59) as u32) ^ key_a);
    let t = neg64(0x40a7b892e31b1a47).wrapping_mul(v8.rotate_left(27) ^ v8);
    let u = neg64(0x6b2fb644ecceee15).wrapping_mul((t >> 29) ^ t);
    key_a.wrapping_add(i).rotate_left(((i + 3) % 61) as u32) ^ key_b.wrapping_sub(i.wrapping_mul(0x61c8864680b583eb)) ^ u ^ (u >> 31)
}

fn derive_transform_key_pair(path_hash: u64, decode_mode: u32, key32: &[u8; 32]) -> (u64, u64) {
    let lo = path_hash & 0xffffffff;
    let hi = path_hash >> 32;
    let mode = decode_mode as u64;
    let mut a = lo.wrapping_mul(0x9e3779b97f4a7c15)
        ^ hi.wrapping_mul(0xc6a4a7935bd1e995)
        ^ mode.wrapping_mul(0x27d4eb2f165667c5)
        ^ hi.wrapping_mul(mode).rotate_left(17)
        ^ 0x3939716bu64.wrapping_mul(0x85ebca6b5b152487);
    a = mix64_rounds(a);
    for (i, b) in key32.iter().enumerate() {
        a ^= (*b as u64) << ((i * 8) & 0x38);
        a = mix64_rounds(a);
    }
    let mut b = hi.wrapping_mul(0x9e3779b97f4a7c15)
        ^ mode.wrapping_mul(0xc6a4a7935bd1e995)
        ^ lo.wrapping_mul(0x27d4eb2f165667c5)
        ^ lo.wrapping_mul(mode).rotate_left(17)
        ^ 0x30d42d2eu64.wrapping_mul(0x85ebca6b5b152487);
    b = mix64_rounds(b);
    for (i, x) in key32.iter().enumerate() {
        b ^= (*x as u64) << ((i * 8) & 0x38);
        b = mix64_rounds(b);
    }
    (a, b)
}

fn mix64_rounds(mut v: u64) -> u64 {
    v = ((v >> 30) ^ v).wrapping_mul(0xbf58476d1ce4e5b9);
    v = ((v >> 27) ^ v).wrapping_mul(0x94d049bb133111eb);
    (v >> 31) ^ v
}

fn dynamic_prefix_seed_key(token32: &[u8; 32], mode: u32) -> [u8; 32] {
    let mut material = [0u8; 0x2c];
    material[0..32].copy_from_slice(token32);
    material[0x20..0x24].copy_from_slice(&mode.to_le_bytes());
    material[0x24..0x28].copy_from_slice(&3u32.to_le_bytes());
    material[0x28..0x2c].copy_from_slice(&(0x550890a4u32 ^ mode ^ 0x45455344u32).to_le_bytes());
    sha256(&material)
}

fn hash_token32_a(token: &[u8; 32]) -> u32 {
    let v0 = read_u32_le(token, 0).unwrap() ^ read_u32_le(token, 0x10).unwrap();
    let v1 = read_u32_le(token, 4).unwrap() ^ read_u32_le(token, 0x14).unwrap();
    let v2 = read_u32_le(token, 8).unwrap() ^ read_u32_le(token, 0x18).unwrap();
    let v3 = read_u32_le(token, 0x0c).unwrap() ^ read_u32_le(token, 0x1c).unwrap();
    let mut x = v0 ^ v1 ^ v2 ^ v3;
    x = ((x >> 16) ^ x).wrapping_mul(0x85ebca77);
    x = ((x >> 13) ^ x).wrapping_mul(0xc2b2ae3d);
    (x >> 16) ^ x
}

fn hash_token32_b(token: &[u8; 32]) -> u32 {
    read_u32_le(token, 0x18).unwrap() ^ read_u32_le(token, 0x14).unwrap()
}

fn resolve_dat_containers_for_image(request_path: &str) -> Vec<PathBuf> {
    let p = normalize_url_path(request_path).trim_end_matches('_').to_string();
    let parts: Vec<&str> = p.split('/').collect();
    if parts.len() < 2 || !parts[0].eq_ignore_ascii_case("img") {
        return Vec::new();
    }
    let dir = parts[..parts.len() - 1].join("/");
    let candidates = [
        Path::new(parts[0]).join(parts[1]).join(format!("{}.dat", parts[1])),
        PathBuf::from(&dir).join(format!("{}.dat", Path::new(&dir).file_name().and_then(|v| v.to_str()).unwrap_or(""))),
    ];
    let root = root_dir();
    let mut out = Vec::new();
    for c in candidates {
        if root.join(&c).is_file() && !out.contains(&c) {
            out.push(c);
        }
    }
    out
}

fn inflate_raw(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoder = DeflateDecoder::new(input);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).map_err(|e| format!("inflate raw failed: {e}"))?;
    Ok(out)
}

fn sha256(input: &[u8]) -> [u8; 32] {
    Sha256::digest(input).into()
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

fn read_u32_le(buf: &[u8], off: usize) -> Result<u32, String> {
    let bytes: [u8; 4] = buf
        .get(off..off + 4)
        .ok_or_else(|| format!("u32 read out of range at {off:x}"))?
        .try_into()
        .unwrap();
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64_le(buf: &[u8], off: usize) -> Result<u64, String> {
    let bytes: [u8; 8] = buf
        .get(off..off + 8)
        .ok_or_else(|| format!("u64 read out of range at {off:x}"))?
        .try_into()
        .unwrap();
    Ok(u64::from_le_bytes(bytes))
}

fn parse_hex_u32(input: &str) -> u32 {
    let mut out = 0u32;
    for b in input.bytes() {
        if let Some(v) = hex_val(b) {
            out = (out << 4) | v as u32;
        }
    }
    out
}

fn hex_decode(input: &[u8]) -> Result<Vec<u8>, String> {
    if input.len() % 2 != 0 {
        return Err("odd hex length".to_string());
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    let mut i = 0;
    while i < input.len() {
        let a = hex_val(input[i]).ok_or_else(|| "bad hex".to_string())?;
        let b = hex_val(input[i + 1]).ok_or_else(|| "bad hex".to_string())?;
        out.push((a << 4) | b);
        i += 2;
    }
    Ok(out)
}

const fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn to_hex_lower(input: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(input.len() * 2);
    for b in input {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

const fn neg64(x: u64) -> u64 {
    0u64.wrapping_sub(x)
}

const fn hex32(s: &str) -> [u8; 32] {
    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (hex_val_const(bytes[i * 2]) << 4) | hex_val_const(bytes[i * 2 + 1]);
        i += 1;
    }
    out
}

const fn hex31(s: &str) -> [u8; 31] {
    let bytes = s.as_bytes();
    let mut out = [0u8; 31];
    let mut i = 0;
    while i < 31 {
        out[i] = (hex_val_const(bytes[i * 2]) << 4) | hex_val_const(bytes[i * 2 + 1]);
        i += 1;
    }
    out
}

const fn hex16(s: &str) -> [u8; 16] {
    let bytes = s.as_bytes();
    let mut out = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        out[i] = (hex_val_const(bytes[i * 2]) << 4) | hex_val_const(bytes[i * 2 + 1]);
        i += 1;
    }
    out
}

const fn hex8(s: &str) -> [u8; 8] {
    let bytes = s.as_bytes();
    let mut out = [0u8; 8];
    let mut i = 0;
    while i < 8 {
        out[i] = (hex_val_const(bytes[i * 2]) << 4) | hex_val_const(bytes[i * 2 + 1]);
        i += 1;
    }
    out
}

const fn hex12(s: &str) -> [u8; 12] {
    let bytes = s.as_bytes();
    let mut out = [0u8; 12];
    let mut i = 0;
    while i < 12 {
        out[i] = (hex_val_const(bytes[i * 2]) << 4) | hex_val_const(bytes[i * 2 + 1]);
        i += 1;
    }
    out
}

const fn hex179(s: &str) -> [u8; 179] {
    let bytes = s.as_bytes();
    let mut out = [0u8; 179];
    let mut i = 0;
    while i < 179 {
        out[i] = (hex_val_const(bytes[i * 2]) << 4) | hex_val_const(bytes[i * 2 + 1]);
        i += 1;
    }
    out
}

const fn hex_val_const(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}
