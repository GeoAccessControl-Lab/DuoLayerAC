//! C ABI for the NTT-accelerated PolyLock ring-lattice core.

mod core;

pub use core::{
    derive_data_key, DataCiphertext, DecapsulationContext, Policy, SetupConfig, System,
    VersionedProfile,
};
use core::{LockCiphertext, ResolvedPolicy, UserKey, SEED_BYTES};
use std::{
    ffi::{c_char, CStr, CString},
    panic::{catch_unwind, AssertUnwindSafe},
    ptr,
};

#[repr(C)]
pub struct PolyLockSystem {
    inner: System,
}
#[repr(C)]
pub struct PolyLockUserKey {
    inner: UserKey,
}
#[repr(C)]
pub struct PolyLockResolvedPolicy {
    inner: ResolvedPolicy,
}
#[repr(C)]
pub struct PolyLockCiphertext {
    inner: LockCiphertext,
}
#[repr(C)]
pub struct PolyLockDecapsulationContext {
    inner: DecapsulationContext,
}

unsafe fn read_c_string<'a>(value: *const c_char, label: &str) -> Result<&'a str, String> {
    if value.is_null() {
        return Err(format!("{label} is null"));
    }
    CStr::from_ptr(value)
        .to_str()
        .map_err(|e| format!("{label} is not UTF-8: {e}"))
}
unsafe fn read_bytes<'a>(value: *const u8, length: usize, label: &str) -> Result<&'a [u8], String> {
    if value.is_null() || length == 0 {
        return Err(format!("{label} is empty"));
    }
    Ok(std::slice::from_raw_parts(value, length))
}
unsafe fn set_error(out: *mut *mut c_char, message: impl Into<String>) {
    if !out.is_null() {
        *out = CString::new(message.into().replace('\0', " "))
            .unwrap()
            .into_raw()
    }
}
fn c_string(value: impl Into<String>) -> *mut c_char {
    CString::new(value.into().replace('\0', " "))
        .unwrap()
        .into_raw()
}
fn return_bytes(
    result: Result<Vec<u8>, String>,
    length_out: *mut usize,
    error_out: *mut *mut c_char,
) -> *mut u8 {
    match result {
        Ok(bytes) => {
            let boxed = bytes.into_boxed_slice();
            let length = boxed.len();
            let pointer = Box::into_raw(boxed) as *mut u8;
            unsafe {
                if !length_out.is_null() {
                    *length_out = length;
                }
            }
            pointer
        }
        Err(error) => {
            unsafe { set_error(error_out, error) };
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn polylock_setup(
    config_json: *const c_char,
    error_out: *mut *mut c_char,
) -> *mut PolyLockSystem {
    if !error_out.is_null() {
        *error_out = ptr::null_mut()
    }
    match catch_unwind(AssertUnwindSafe(|| -> Result<PolyLockSystem, String> {
        let config: SetupConfig = serde_json::from_str(read_c_string(config_json, "config_json")?)
            .map_err(|e| format!("invalid setup JSON: {e}"))?;
        Ok(PolyLockSystem {
            inner: System::setup(config)?,
        })
    })) {
        Ok(Ok(x)) => Box::into_raw(Box::new(x)),
        Ok(Err(e)) => {
            set_error(error_out, e);
            ptr::null_mut()
        }
        Err(_) => {
            set_error(error_out, "panic in polylock_setup");
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn polylock_system_public_serialize(
    system: *const PolyLockSystem,
    length_out: *mut usize,
    error_out: *mut *mut c_char,
) -> *mut u8 {
    if !length_out.is_null() {
        *length_out = 0;
    }
    if !error_out.is_null() {
        *error_out = ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| -> Result<Vec<u8>, String> {
        let system = system.as_ref().ok_or("system is null")?;
        system.inner.serialize_public()
    })) {
        Ok(result) => return_bytes(result, length_out, error_out),
        Err(_) => {
            set_error(error_out, "panic in polylock_system_public_serialize");
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn polylock_system_master_serialize(
    system: *const PolyLockSystem,
    length_out: *mut usize,
    error_out: *mut *mut c_char,
) -> *mut u8 {
    if !length_out.is_null() {
        *length_out = 0;
    }
    if !error_out.is_null() {
        *error_out = ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| -> Result<Vec<u8>, String> {
        let system = system.as_ref().ok_or("system is null")?;
        system.inner.serialize_master_secret()
    })) {
        Ok(result) => return_bytes(result, length_out, error_out),
        Err(_) => {
            set_error(error_out, "panic in polylock_system_master_serialize");
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn polylock_system_deserialize_public(
    input: *const u8,
    length: usize,
    error_out: *mut *mut c_char,
) -> *mut PolyLockSystem {
    if !error_out.is_null() {
        *error_out = ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| -> Result<PolyLockSystem, String> {
        let bytes = read_bytes(input, length, "public system")?;
        Ok(PolyLockSystem {
            inner: System::deserialize_public(bytes)?,
        })
    })) {
        Ok(Ok(system)) => Box::into_raw(Box::new(system)),
        Ok(Err(error)) => {
            set_error(error_out, error);
            ptr::null_mut()
        }
        Err(_) => {
            set_error(error_out, "panic in polylock_system_deserialize_public");
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn polylock_system_deserialize_authority(
    public_input: *const u8,
    public_length: usize,
    master_input: *const u8,
    master_length: usize,
    error_out: *mut *mut c_char,
) -> *mut PolyLockSystem {
    if !error_out.is_null() {
        *error_out = ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| -> Result<PolyLockSystem, String> {
        let public = read_bytes(public_input, public_length, "public system")?;
        let master = read_bytes(master_input, master_length, "master secret")?;
        Ok(PolyLockSystem {
            inner: System::deserialize_authority(public, master)?,
        })
    })) {
        Ok(Ok(system)) => Box::into_raw(Box::new(system)),
        Ok(Err(error)) => {
            set_error(error_out, error);
            ptr::null_mut()
        }
        Err(_) => {
            set_error(error_out, "panic in polylock_system_deserialize_authority");
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn polylock_keygen(
    system: *const PolyLockSystem,
    attributes_json: *const c_char,
    error_out: *mut *mut c_char,
) -> *mut PolyLockUserKey {
    if !error_out.is_null() {
        *error_out = ptr::null_mut()
    }
    match catch_unwind(AssertUnwindSafe(|| -> Result<PolyLockUserKey, String> {
        let system = system.as_ref().ok_or("system is null")?;
        let a: Vec<u8> = serde_json::from_str(read_c_string(attributes_json, "attributes_json")?)
            .map_err(|e| format!("invalid attributes JSON: {e}"))?;
        Ok(PolyLockUserKey {
            inner: system.inner.keygen(a)?,
        })
    })) {
        Ok(Ok(x)) => Box::into_raw(Box::new(x)),
        Ok(Err(e)) => {
            set_error(error_out, e);
            ptr::null_mut()
        }
        Err(_) => {
            set_error(error_out, "panic in polylock_keygen");
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn polylock_keygen_versioned(
    system: *const PolyLockSystem,
    attributes_json: *const c_char,
    version: u64,
    error_out: *mut *mut c_char,
) -> *mut PolyLockUserKey {
    if !error_out.is_null() {
        *error_out = ptr::null_mut()
    }
    match catch_unwind(AssertUnwindSafe(|| -> Result<PolyLockUserKey, String> {
        let system = system.as_ref().ok_or("system is null")?;
        let attributes: Vec<u8> =
            serde_json::from_str(read_c_string(attributes_json, "attributes_json")?)
                .map_err(|error| format!("invalid attributes JSON: {error}"))?;
        Ok(PolyLockUserKey {
            inner: system.inner.keygen_versioned(attributes, version)?,
        })
    })) {
        Ok(Ok(key)) => Box::into_raw(Box::new(key)),
        Ok(Err(error)) => {
            set_error(error_out, error);
            ptr::null_mut()
        }
        Err(_) => {
            set_error(error_out, "panic in polylock_keygen_versioned");
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn polylock_preresolve(
    system: *const PolyLockSystem,
    policy_json: *const c_char,
    error_out: *mut *mut c_char,
) -> *mut PolyLockResolvedPolicy {
    if !error_out.is_null() {
        *error_out = ptr::null_mut()
    }
    match catch_unwind(AssertUnwindSafe(
        || -> Result<PolyLockResolvedPolicy, String> {
            let system = system.as_ref().ok_or("system is null")?;
            let p: Policy = serde_json::from_str(read_c_string(policy_json, "policy_json")?)
                .map_err(|e| format!("invalid policy JSON: {e}"))?;
            Ok(PolyLockResolvedPolicy {
                inner: system.inner.preresolve(&p)?,
            })
        },
    )) {
        Ok(Ok(x)) => Box::into_raw(Box::new(x)),
        Ok(Err(e)) => {
            set_error(error_out, e);
            ptr::null_mut()
        }
        Err(_) => {
            set_error(error_out, "panic in polylock_preresolve");
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn polylock_preresolve_versioned_profiles(
    system: *const PolyLockSystem,
    profiles_json: *const c_char,
    error_out: *mut *mut c_char,
) -> *mut PolyLockResolvedPolicy {
    if !error_out.is_null() {
        *error_out = ptr::null_mut()
    }
    match catch_unwind(AssertUnwindSafe(
        || -> Result<PolyLockResolvedPolicy, String> {
            let system = system.as_ref().ok_or("system is null")?;
            let profiles: Vec<VersionedProfile> =
                serde_json::from_str(read_c_string(profiles_json, "profiles_json")?)
                    .map_err(|error| format!("invalid versioned profiles JSON: {error}"))?;
            Ok(PolyLockResolvedPolicy {
                inner: system.inner.preresolve_versioned_profiles(&profiles)?,
            })
        },
    )) {
        Ok(Ok(resolved)) => Box::into_raw(Box::new(resolved)),
        Ok(Err(error)) => {
            set_error(error_out, error);
            ptr::null_mut()
        }
        Err(_) => {
            set_error(error_out, "panic in polylock_preresolve_versioned_profiles");
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn polylock_encaps(
    system: *const PolyLockSystem,
    resolved: *const PolyLockResolvedPolicy,
    seed_hex: *const c_char,
    error_out: *mut *mut c_char,
) -> *mut PolyLockCiphertext {
    if !error_out.is_null() {
        *error_out = ptr::null_mut()
    }
    match catch_unwind(AssertUnwindSafe(
        || -> Result<PolyLockCiphertext, String> {
            let system = system.as_ref().ok_or("system is null")?;
            let resolved = resolved.as_ref().ok_or("resolved policy is null")?;
            let v = hex::decode(read_c_string(seed_hex, "seed_hex")?)
                .map_err(|e| format!("invalid seed hex: {e}"))?;
            let seed: [u8; SEED_BYTES] = v.try_into().map_err(|_| "KEM seed must be 16 bytes")?;
            Ok(PolyLockCiphertext {
                inner: system.inner.encaps(&resolved.inner, &seed)?,
            })
        },
    )) {
        Ok(Ok(x)) => Box::into_raw(Box::new(x)),
        Ok(Err(e)) => {
            set_error(error_out, e);
            ptr::null_mut()
        }
        Err(_) => {
            set_error(error_out, "panic in polylock_encaps");
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn polylock_reencaps(
    system: *const PolyLockSystem,
    old_resolved: *const PolyLockResolvedPolicy,
    new_resolved: *const PolyLockResolvedPolicy,
    old_ciphertext: *const PolyLockCiphertext,
    seed_hex: *const c_char,
    refreshed_out: *mut usize,
    reused_out: *mut usize,
    error_out: *mut *mut c_char,
) -> *mut PolyLockCiphertext {
    if !refreshed_out.is_null() {
        *refreshed_out = 0;
    }
    if !reused_out.is_null() {
        *reused_out = 0;
    }
    if !error_out.is_null() {
        *error_out = ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(
        || -> Result<(PolyLockCiphertext, usize, usize), String> {
            let system = system.as_ref().ok_or("system is null")?;
            let old_resolved = old_resolved.as_ref().ok_or("old resolved policy is null")?;
            let new_resolved = new_resolved.as_ref().ok_or("new resolved policy is null")?;
            let old_ciphertext = old_ciphertext.as_ref().ok_or("old ciphertext is null")?;
            let value = hex::decode(read_c_string(seed_hex, "seed_hex")?)
                .map_err(|error| format!("invalid seed hex: {error}"))?;
            let seed: [u8; SEED_BYTES] =
                value.try_into().map_err(|_| "KEM seed must be 16 bytes")?;
            let result = system.inner.reencaps(
                &old_resolved.inner,
                &new_resolved.inner,
                &old_ciphertext.inner,
                &seed,
            )?;
            Ok((
                PolyLockCiphertext {
                    inner: result.ciphertext,
                },
                result.refreshed_buckets,
                result.reused_buckets,
            ))
        },
    )) {
        Ok(Ok((ciphertext, refreshed, reused))) => {
            if !refreshed_out.is_null() {
                *refreshed_out = refreshed;
            }
            if !reused_out.is_null() {
                *reused_out = reused;
            }
            Box::into_raw(Box::new(ciphertext))
        }
        Ok(Err(error)) => {
            set_error(error_out, error);
            ptr::null_mut()
        }
        Err(_) => {
            set_error(error_out, "panic in polylock_reencaps");
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn polylock_decaps(
    system: *const PolyLockSystem,
    user_key: *const PolyLockUserKey,
    ciphertext: *const PolyLockCiphertext,
    data_json: *const c_char,
    error_out: *mut *mut c_char,
) -> *mut c_char {
    if !error_out.is_null() {
        *error_out = ptr::null_mut()
    }
    match catch_unwind(AssertUnwindSafe(|| -> Result<Option<[u8; 32]>, String> {
        let system = system.as_ref().ok_or("system is null")?;
        let key = user_key.as_ref().ok_or("user key is null")?;
        let ct = ciphertext.as_ref().ok_or("ciphertext is null")?;
        let data: DataCiphertext =
            serde_json::from_str(read_c_string(data_json, "data_cipher_json")?)
                .map_err(|e| format!("invalid data ciphertext JSON: {e}"))?;
        system.inner.decaps(&key.inner, &ct.inner, &data)
    })) {
        Ok(Ok(Some(k))) => c_string(hex::encode(k)),
        Ok(Ok(None)) => ptr::null_mut(),
        Ok(Err(e)) => {
            set_error(error_out, e);
            ptr::null_mut()
        }
        Err(_) => {
            set_error(error_out, "panic in polylock_decaps");
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn polylock_decapsulation_context_new(
    security_profile: *const c_char,
    error_out: *mut *mut c_char,
) -> *mut PolyLockDecapsulationContext {
    if !error_out.is_null() {
        *error_out = ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(
        || -> Result<PolyLockDecapsulationContext, String> {
            Ok(PolyLockDecapsulationContext {
                inner: DecapsulationContext::new(read_c_string(
                    security_profile,
                    "security_profile",
                )?)?,
            })
        },
    )) {
        Ok(Ok(context)) => Box::into_raw(Box::new(context)),
        Ok(Err(error)) => {
            set_error(error_out, error);
            ptr::null_mut()
        }
        Err(_) => {
            set_error(error_out, "panic in polylock_decapsulation_context_new");
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn polylock_decaps_with_context(
    context: *const PolyLockDecapsulationContext,
    user_key: *const PolyLockUserKey,
    ciphertext: *const PolyLockCiphertext,
    data_json: *const c_char,
    error_out: *mut *mut c_char,
) -> *mut c_char {
    if !error_out.is_null() {
        *error_out = ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| -> Result<Option<[u8; 32]>, String> {
        let context = context.as_ref().ok_or("decapsulation context is null")?;
        let key = user_key.as_ref().ok_or("user key is null")?;
        let ciphertext = ciphertext.as_ref().ok_or("ciphertext is null")?;
        let data: DataCiphertext =
            serde_json::from_str(read_c_string(data_json, "data_cipher_json")?)
                .map_err(|error| format!("invalid data ciphertext JSON: {error}"))?;
        context.inner.decaps(&key.inner, &ciphertext.inner, &data)
    })) {
        Ok(Ok(Some(key))) => c_string(hex::encode(key)),
        Ok(Ok(None)) => ptr::null_mut(),
        Ok(Err(error)) => {
            set_error(error_out, error);
            ptr::null_mut()
        }
        Err(_) => {
            set_error(error_out, "panic in polylock_decaps_with_context");
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn polylock_decaps_serialized_with_context(
    context: *const PolyLockDecapsulationContext,
    user_key: *const PolyLockUserKey,
    ciphertext: *const u8,
    ciphertext_length: usize,
    data_json: *const c_char,
    error_out: *mut *mut c_char,
) -> *mut c_char {
    if !error_out.is_null() {
        *error_out = ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| -> Result<Option<[u8; 32]>, String> {
        let context = context.as_ref().ok_or("decapsulation context is null")?;
        let key = user_key.as_ref().ok_or("user key is null")?;
        if ciphertext.is_null() || ciphertext_length == 0 {
            return Err("serialized ciphertext is empty".into());
        }
        let ciphertext = std::slice::from_raw_parts(ciphertext, ciphertext_length);
        let data: DataCiphertext =
            serde_json::from_str(read_c_string(data_json, "data_cipher_json")?)
                .map_err(|error| format!("invalid data ciphertext JSON: {error}"))?;
        context
            .inner
            .decaps_serialized(&key.inner, ciphertext, &data)
    })) {
        Ok(Ok(Some(key))) => c_string(hex::encode(key)),
        Ok(Ok(None)) => ptr::null_mut(),
        Ok(Err(error)) => {
            set_error(error_out, error);
            ptr::null_mut()
        }
        Err(_) => {
            set_error(
                error_out,
                "panic in polylock_decaps_serialized_with_context",
            );
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn polylock_derive_data_key(
    seed_hex: *const c_char,
    aad_hex: *const c_char,
    error_out: *mut *mut c_char,
) -> *mut c_char {
    if !error_out.is_null() {
        *error_out = ptr::null_mut()
    }
    match catch_unwind(AssertUnwindSafe(|| -> Result<[u8; 32], String> {
        let v = hex::decode(read_c_string(seed_hex, "seed_hex")?).map_err(|e| e.to_string())?;
        let seed: [u8; SEED_BYTES] = v.try_into().map_err(|_| "KEM seed must be 16 bytes")?;
        let aad = hex::decode(read_c_string(aad_hex, "aad_hex")?).map_err(|e| e.to_string())?;
        Ok(derive_data_key(&seed, &aad))
    })) {
        Ok(Ok(k)) => c_string(hex::encode(k)),
        Ok(Err(e)) => {
            set_error(error_out, e);
            ptr::null_mut()
        }
        Err(_) => {
            set_error(error_out, "panic in polylock_derive_data_key");
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn polylock_system_metadata(system: *const PolyLockSystem) -> *mut c_char {
    system
        .as_ref()
        .map(|s| c_string(serde_json::to_string(&s.inner.metadata()).unwrap()))
        .unwrap_or(ptr::null_mut())
}
#[no_mangle]
pub unsafe extern "C" fn polylock_resolved_metadata(
    resolved: *const PolyLockResolvedPolicy,
) -> *mut c_char {
    resolved
        .as_ref()
        .map(|r| c_string(serde_json::to_string(&r.inner.metadata()).unwrap()))
        .unwrap_or(ptr::null_mut())
}
#[no_mangle]
pub unsafe extern "C" fn polylock_ciphertext_serialized_size(
    ciphertext: *const PolyLockCiphertext,
) -> usize {
    ciphertext
        .as_ref()
        .map(|value| value.inner.serialized_size())
        .unwrap_or(0)
}
#[no_mangle]
pub unsafe extern "C" fn polylock_ciphertext_serialize(
    ciphertext: *const PolyLockCiphertext,
    length_out: *mut usize,
    error_out: *mut *mut c_char,
) -> *mut u8 {
    if !length_out.is_null() {
        *length_out = 0;
    }
    if !error_out.is_null() {
        *error_out = ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| -> Result<Box<[u8]>, String> {
        let ciphertext = ciphertext.as_ref().ok_or("ciphertext is null")?;
        Ok(ciphertext.inner.serialize()?.into_boxed_slice())
    })) {
        Ok(Ok(bytes)) => {
            let length = bytes.len();
            let pointer = Box::into_raw(bytes) as *mut u8;
            if !length_out.is_null() {
                *length_out = length;
            }
            pointer
        }
        Ok(Err(error)) => {
            set_error(error_out, error);
            ptr::null_mut()
        }
        Err(_) => {
            set_error(error_out, "panic in polylock_ciphertext_serialize");
            ptr::null_mut()
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn polylock_ciphertext_deserialize(
    input: *const u8,
    length: usize,
    error_out: *mut *mut c_char,
) -> *mut PolyLockCiphertext {
    if !error_out.is_null() {
        *error_out = ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(
        || -> Result<PolyLockCiphertext, String> {
            if input.is_null() || length == 0 {
                return Err("serialized ciphertext is empty".into());
            }
            let bytes = std::slice::from_raw_parts(input, length);
            Ok(PolyLockCiphertext {
                inner: LockCiphertext::deserialize(bytes)?,
            })
        },
    )) {
        Ok(Ok(ciphertext)) => Box::into_raw(Box::new(ciphertext)),
        Ok(Err(error)) => {
            set_error(error_out, error);
            ptr::null_mut()
        }
        Err(_) => {
            set_error(error_out, "panic in polylock_ciphertext_deserialize");
            ptr::null_mut()
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn polylock_user_key_serialized_size(
    user_key: *const PolyLockUserKey,
) -> usize {
    user_key
        .as_ref()
        .map(|value| value.inner.serialized_size())
        .unwrap_or(0)
}
#[no_mangle]
pub unsafe extern "C" fn polylock_user_key_serialize(
    user_key: *const PolyLockUserKey,
    length_out: *mut usize,
    error_out: *mut *mut c_char,
) -> *mut u8 {
    if !length_out.is_null() {
        *length_out = 0;
    }
    if !error_out.is_null() {
        *error_out = ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| -> Result<Box<[u8]>, String> {
        let user_key = user_key.as_ref().ok_or("user key is null")?;
        Ok(user_key.inner.serialize()?.into_boxed_slice())
    })) {
        Ok(Ok(bytes)) => {
            let length = bytes.len();
            let pointer = Box::into_raw(bytes) as *mut u8;
            if !length_out.is_null() {
                *length_out = length;
            }
            pointer
        }
        Ok(Err(error)) => {
            set_error(error_out, error);
            ptr::null_mut()
        }
        Err(_) => {
            set_error(error_out, "panic in polylock_user_key_serialize");
            ptr::null_mut()
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn polylock_user_key_deserialize(
    input: *const u8,
    length: usize,
    error_out: *mut *mut c_char,
) -> *mut PolyLockUserKey {
    if !error_out.is_null() {
        *error_out = ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| -> Result<PolyLockUserKey, String> {
        if input.is_null() || length == 0 {
            return Err("serialized user key is empty".into());
        }
        let bytes = std::slice::from_raw_parts(input, length);
        Ok(PolyLockUserKey {
            inner: UserKey::deserialize(bytes)?,
        })
    })) {
        Ok(Ok(user_key)) => Box::into_raw(Box::new(user_key)),
        Ok(Err(error)) => {
            set_error(error_out, error);
            ptr::null_mut()
        }
        Err(_) => {
            set_error(error_out, "panic in polylock_user_key_deserialize");
            ptr::null_mut()
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn polylock_system_free(x: *mut PolyLockSystem) {
    if !x.is_null() {
        drop(Box::from_raw(x))
    }
}
#[no_mangle]
pub unsafe extern "C" fn polylock_decapsulation_context_free(
    context: *mut PolyLockDecapsulationContext,
) {
    if !context.is_null() {
        drop(Box::from_raw(context))
    }
}
#[no_mangle]
pub unsafe extern "C" fn polylock_user_key_free(x: *mut PolyLockUserKey) {
    if !x.is_null() {
        drop(Box::from_raw(x))
    }
}
#[no_mangle]
pub unsafe extern "C" fn polylock_resolved_free(x: *mut PolyLockResolvedPolicy) {
    if !x.is_null() {
        drop(Box::from_raw(x))
    }
}
#[no_mangle]
pub unsafe extern "C" fn polylock_ciphertext_free(x: *mut PolyLockCiphertext) {
    if !x.is_null() {
        drop(Box::from_raw(x))
    }
}
#[no_mangle]
pub unsafe extern "C" fn polylock_string_free(x: *mut c_char) {
    if !x.is_null() {
        drop(CString::from_raw(x))
    }
}
#[no_mangle]
pub unsafe extern "C" fn polylock_bytes_free(x: *mut u8, length: usize) {
    if !x.is_null() && length != 0 {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(x, length)))
    }
}
