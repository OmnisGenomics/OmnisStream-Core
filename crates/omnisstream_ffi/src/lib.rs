use std::cell::RefCell;
use std::ffi::CString;
use std::io::Read;
use std::os::raw::{c_char, c_int, c_uchar};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::slice;

use omnisstream::{Manifest, PartStore, Reader};

pub const OS_OK: c_int = 0;
pub const OS_INVALID_ARGUMENT: c_int = 1;
pub const OS_IO_ERROR: c_int = 2;
pub const OS_CORRUPT_DATA: c_int = 3;
pub const OS_SPEC_VIOLATION: c_int = 4;
pub const OS_INTERNAL: c_int = 5;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OsDigest {
    pub bytes: [c_uchar; 32],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OsSpan {
    pub ptr: *const c_uchar,
    pub len: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OsOwnedBytes {
    pub ptr: *mut c_uchar,
    pub len: usize,
}

pub enum OsPartStore {}
pub enum OsManifest {}

struct PartStoreHandle {
    inner: PartStore,
}

struct ManifestHandle {
    inner: Manifest,
}

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

fn clear_last_error() {
    LAST_ERROR.with(|cell| {
        *cell.borrow_mut() = None;
    });
}

fn set_last_error(message: impl AsRef<str>) {
    let msg = message.as_ref();
    let c = CString::new(msg).unwrap_or_else(|_| CString::new("error").expect("CString"));
    LAST_ERROR.with(|cell| {
        *cell.borrow_mut() = Some(c);
    });
}

fn last_error_ptr() -> *const c_char {
    static EMPTY: &[u8] = b"\0";
    LAST_ERROR.with(|cell| match cell.borrow().as_ref() {
        Some(s) => s.as_ptr(),
        None => EMPTY.as_ptr() as *const c_char,
    })
}

fn span_as_slice<'a>(span: OsSpan) -> Result<&'a [u8], c_int> {
    if span.len == 0 {
        return Ok(&[]);
    }
    if span.ptr.is_null() {
        set_last_error("span.ptr is null");
        return Err(OS_INVALID_ARGUMENT);
    }
    unsafe { Ok(slice::from_raw_parts(span.ptr, span.len)) }
}

fn span_to_utf8_string(span: OsSpan) -> Result<String, c_int> {
    let bytes = span_as_slice(span)?;
    std::str::from_utf8(bytes)
        .map(|s| s.to_string())
        .map_err(|e| {
            set_last_error(format!("utf8 decode failed: {e}"));
            OS_INVALID_ARGUMENT
        })
}

fn with_boundary<F>(f: F) -> c_int
where
    F: FnOnce() -> Result<(), c_int>,
{
    clear_last_error();
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => OS_OK,
        Ok(Err(code)) => code,
        Err(_) => {
            set_last_error("panic across FFI boundary");
            OS_INTERNAL
        }
    }
}

fn map_io(err: std::io::Error) -> c_int {
    set_last_error(err.to_string());
    OS_IO_ERROR
}

#[no_mangle]
pub extern "C" fn os_version_major() -> u32 {
    env!("CARGO_PKG_VERSION_MAJOR").parse::<u32>().unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn os_version_minor() -> u32 {
    env!("CARGO_PKG_VERSION_MINOR").parse::<u32>().unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn os_version_patch() -> u32 {
    env!("CARGO_PKG_VERSION_PATCH").parse::<u32>().unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn os_last_error_message() -> *const c_char {
    last_error_ptr()
}

#[no_mangle]
pub extern "C" fn os_clear_last_error() {
    clear_last_error();
}

#[no_mangle]
/// # Safety
/// - `root_utf8.ptr` must be valid for `root_utf8.len` bytes for the duration of the call.
/// - `out_store` must be non-null and writable.
/// - On success, `*out_store` must be released with `os_partstore_close` exactly once.
pub unsafe extern "C" fn os_partstore_open(
    root_utf8: OsSpan,
    out_store: *mut *mut OsPartStore,
) -> c_int {
    with_boundary(|| {
        if out_store.is_null() {
            set_last_error("out_store is null");
            return Err(OS_INVALID_ARGUMENT);
        }

        let root = span_to_utf8_string(root_utf8)?;
        if root.trim().is_empty() {
            set_last_error("root path is empty");
            return Err(OS_INVALID_ARGUMENT);
        }

        let store = PartStore::new(root.as_str()).map_err(map_io)?;
        let boxed = Box::new(PartStoreHandle { inner: store });
        unsafe { *out_store = Box::into_raw(boxed) as *mut OsPartStore };
        Ok(())
    })
}

#[no_mangle]
/// # Safety
/// - `store` must be a pointer returned by `os_partstore_open` (or null).
/// - `store` must not be used after this call.
/// - `store` must not be closed more than once.
pub unsafe extern "C" fn os_partstore_close(store: *mut OsPartStore) {
    clear_last_error();
    if store.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        drop(Box::from_raw(store as *mut PartStoreHandle));
    }));
}

#[no_mangle]
/// # Safety
/// - `store` must be a pointer returned by `os_partstore_open`.
/// - `data.ptr` must be valid for `data.len` bytes for the duration of the call.
/// - `out_digest` must be non-null and writable.
pub unsafe extern "C" fn os_partstore_put(
    store: *mut OsPartStore,
    data: OsSpan,
    out_digest: *mut OsDigest,
) -> c_int {
    with_boundary(|| {
        if store.is_null() {
            set_last_error("store is null");
            return Err(OS_INVALID_ARGUMENT);
        }
        if out_digest.is_null() {
            set_last_error("out_digest is null");
            return Err(OS_INVALID_ARGUMENT);
        }
        let bytes = span_as_slice(data)?;

        let handle = unsafe { &mut *(store as *mut PartStoreHandle) };
        let digest = handle.inner.put_bytes(bytes).map_err(map_io)?;

        let mut out = OsDigest { bytes: [0; 32] };
        out.bytes.copy_from_slice(digest.as_bytes());
        unsafe { *out_digest = out };
        Ok(())
    })
}

#[no_mangle]
/// # Safety
/// - `store` must be a pointer returned by `os_partstore_open`.
/// - `digest` must be non-null and point to a valid `OsDigest`.
/// - `out_bytes` must be non-null and writable.
/// - On success, `out_bytes->ptr` must be released with `os_owned_bytes_free`.
pub unsafe extern "C" fn os_partstore_get(
    store: *mut OsPartStore,
    digest: *const OsDigest,
    out_bytes: *mut OsOwnedBytes,
) -> c_int {
    with_boundary(|| {
        if store.is_null() {
            set_last_error("store is null");
            return Err(OS_INVALID_ARGUMENT);
        }
        if digest.is_null() {
            set_last_error("digest is null");
            return Err(OS_INVALID_ARGUMENT);
        }
        if out_bytes.is_null() {
            set_last_error("out_bytes is null");
            return Err(OS_INVALID_ARGUMENT);
        }

        let handle = unsafe { &mut *(store as *mut PartStoreHandle) };
        let digest_bytes = unsafe { &(*digest).bytes };
        let mut digest_arr = [0_u8; 32];
        digest_arr.copy_from_slice(digest_bytes);

        let blake = omnisstream::api::Blake3Digest::from_bytes(digest_arr);
        let mut f = handle.inner.open(blake).map_err(map_io)?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).map_err(map_io)?;
        write_owned_bytes(out_bytes, buf);
        Ok(())
    })
}

#[no_mangle]
/// # Safety
/// - `b` must be non-null and writable.
/// - If `b->ptr` is non-null, it must have been allocated by this library and must not have been
///   freed already.
pub unsafe extern "C" fn os_owned_bytes_free(b: *mut OsOwnedBytes) {
    clear_last_error();
    if b.is_null() {
        return;
    }
    let r = catch_unwind(AssertUnwindSafe(|| unsafe {
        if (*b).ptr.is_null() || (*b).len == 0 {
            (*b).ptr = ptr::null_mut();
            (*b).len = 0;
            return;
        }
        let slice = slice::from_raw_parts_mut((*b).ptr, (*b).len);
        drop(Box::from_raw(slice));
        (*b).ptr = ptr::null_mut();
        (*b).len = 0;
    }));
    if r.is_err() {
        set_last_error("panic across FFI boundary");
    }
}

#[no_mangle]
/// # Safety
/// - `pb_bytes.ptr` must be valid for `pb_bytes.len` bytes for the duration of the call.
/// - `out_manifest` must be non-null and writable.
/// - On success, `*out_manifest` must be released with `os_manifest_free` exactly once.
pub unsafe extern "C" fn os_manifest_load_pb(
    pb_bytes: OsSpan,
    out_manifest: *mut *mut OsManifest,
) -> c_int {
    with_boundary(|| {
        if out_manifest.is_null() {
            set_last_error("out_manifest is null");
            return Err(OS_INVALID_ARGUMENT);
        }
        let bytes = span_as_slice(pb_bytes)?;
        let manifest = Manifest::from_pb_bytes(bytes).map_err(|e| {
            set_last_error(e.to_string());
            OS_CORRUPT_DATA
        })?;

        let boxed = Box::new(ManifestHandle { inner: manifest });
        unsafe { *out_manifest = Box::into_raw(boxed) as *mut OsManifest };
        Ok(())
    })
}

#[no_mangle]
/// # Safety
/// - `m` must be a pointer returned by `os_manifest_load_pb` (or null).
/// - `m` must not be used after this call.
/// - `m` must not be freed more than once.
pub unsafe extern "C" fn os_manifest_free(m: *mut OsManifest) {
    clear_last_error();
    if m.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        drop(Box::from_raw(m as *mut ManifestHandle));
    }));
}

#[no_mangle]
/// # Safety
/// - `m` must be a pointer returned by `os_manifest_load_pb`.
/// - `base_dir_utf8.ptr` must be valid for `base_dir_utf8.len` bytes for the duration of the call.
pub unsafe extern "C" fn os_verify_manifest_on_disk(
    m: *mut OsManifest,
    base_dir_utf8: OsSpan,
) -> c_int {
    with_boundary(|| {
        if m.is_null() {
            set_last_error("manifest is null");
            return Err(OS_INVALID_ARGUMENT);
        }
        let base_dir = span_to_utf8_string(base_dir_utf8)?;
        if base_dir.trim().is_empty() {
            set_last_error("base_dir is empty");
            return Err(OS_INVALID_ARGUMENT);
        }

        let handle = unsafe { &mut *(m as *mut ManifestHandle) };
        let manifest = handle.inner.clone();

        let mut reader = Reader::new(manifest, &base_dir);
        if reader.manifest().needs_part_store() {
            let store =
                PartStore::new(std::path::Path::new(&base_dir).join("parts")).map_err(map_io)?;
            reader = reader.with_part_store(store);
        }

        reader.verify().map_err(|e| match e {
            omnisstream::api::ReaderError::Io(err) => {
                set_last_error(err.to_string());
                OS_IO_ERROR
            }
            omnisstream::api::ReaderError::ManifestValidation(err) => {
                set_last_error(err.to_string());
                OS_SPEC_VIOLATION
            }
            omnisstream::api::ReaderError::HashMismatch { .. }
            | omnisstream::api::ReaderError::UnexpectedEof => {
                set_last_error(e.to_string());
                OS_CORRUPT_DATA
            }
            omnisstream::api::ReaderError::UnsupportedCompression { .. }
            | omnisstream::api::ReaderError::MissingDigest { .. }
            | omnisstream::api::ReaderError::InvalidDigestLength { .. }
            | omnisstream::api::ReaderError::NoPartStoreForDigest
            | omnisstream::api::ReaderError::RangeOutOfBounds => {
                set_last_error(e.to_string());
                OS_SPEC_VIOLATION
            }
        })?;

        Ok(())
    })
}

#[no_mangle]
/// # Safety
/// - `m` must be a pointer returned by `os_manifest_load_pb`.
/// - `out_utf8` must be non-null and writable.
/// - On success, `out_utf8->ptr` must be released with `os_owned_bytes_free`.
pub unsafe extern "C" fn os_manifest_inspect(
    m: *mut OsManifest,
    out_utf8: *mut OsOwnedBytes,
) -> c_int {
    with_boundary(|| {
        if m.is_null() {
            set_last_error("manifest is null");
            return Err(OS_INVALID_ARGUMENT);
        }
        if out_utf8.is_null() {
            set_last_error("out_utf8 is null");
            return Err(OS_INVALID_ARGUMENT);
        }
        let handle = unsafe { &mut *(m as *mut ManifestHandle) };
        let s = handle.inner.inspect();
        write_owned_bytes(out_utf8, s.into_bytes());
        Ok(())
    })
}

fn write_owned_bytes(out: *mut OsOwnedBytes, mut bytes: Vec<u8>) {
    bytes.shrink_to_fit();
    let boxed: Box<[u8]> = bytes.into_boxed_slice();
    let len = boxed.len();
    let ptr = Box::into_raw(boxed) as *mut u8;
    unsafe {
        (*out).ptr = ptr as *mut c_uchar;
        (*out).len = len;
    }
}
