use std::ffi::{CStr, c_char, c_void};
use std::fs::{File, Metadata, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use super::{ClientError, error};

#[link(name = "Foundation", kind = "framework")]
unsafe extern "C" {
    fn NSSearchPathForDirectoriesInDomains(
        directory: usize,
        domains: usize,
        expand_tilde: i8,
    ) -> *mut c_void;
}

#[link(name = "objc")]
unsafe extern "C" {
    fn objc_getClass(name: *const c_char) -> *mut c_void;
    fn sel_registerName(name: *const c_char) -> *mut c_void;
    fn objc_msgSend();
}

unsafe fn send(object: *mut c_void, selector: &CStr) -> *mut c_void {
    let call: unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void =
        unsafe { std::mem::transmute(objc_msgSend as unsafe extern "C" fn()) };
    unsafe { call(object, sel_registerName(selector.as_ptr())) }
}

struct Pool(*mut c_void);
impl Drop for Pool {
    fn drop(&mut self) {
        let call: unsafe extern "C" fn(*mut c_void, *mut c_void) =
            unsafe { std::mem::transmute(objc_msgSend as unsafe extern "C" fn()) };
        unsafe {
            call(self.0, sel_registerName(c"drain".as_ptr()));
        }
    }
}

pub(super) fn state_home() -> Result<PathBuf, ClientError> {
    let pool = Pool(unsafe { send(objc_getClass(c"NSAutoreleasePool".as_ptr()), c"new") });
    if pool.0.is_null() {
        return Err(error("unavailable"));
    }
    // Foundation resolves sandbox containers as well as ordinary user directories.
    let paths = unsafe { NSSearchPathForDirectoriesInDomains(14, 1, 1) };
    let first = unsafe { send(paths, c"firstObject") };
    let text = unsafe { send(first, c"UTF8String") }.cast::<c_char>();
    if text.is_null() {
        return Err(error("unavailable"));
    }
    let path = unsafe { CStr::from_ptr(text) }
        .to_str()
        .map_err(|_| error("unavailable"))?;
    Ok(PathBuf::from(path))
}

pub(super) fn private_path(path: &Path, expected: &Metadata) -> Result<(), ClientError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(super::io_error)?;
    let actual = file.metadata().map_err(super::io_error)?;
    if (actual.dev(), actual.ino()) != (expected.dev(), expected.ino()) {
        return Err(error("unavailable"));
    }
    private_file(&file)
}

struct Acl(*mut c_void);
impl Acl {
    fn new(pointer: *mut c_void) -> Result<Self, ClientError> {
        if pointer.is_null() {
            return Err(error("unavailable"));
        }
        Ok(Self(pointer))
    }
}
impl Drop for Acl {
    fn drop(&mut self) {
        unsafe {
            acl_free(self.0);
        }
    }
}

pub(super) fn private_file(file: &File) -> Result<(), ClientError> {
    let raw = unsafe { acl_get_fd_np(file.as_raw_fd(), 0x100) };
    if raw.is_null() {
        // A valid descriptor reports ENOENT when it has no extended ACL.
        return if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            Ok(())
        } else {
            Err(error("unavailable"))
        };
    }
    let acl = Acl::new(raw)?;
    if unsafe { acl_valid(acl.0) } != 0 {
        return Err(error("unavailable"));
    }
    let mut entry_id = 0;
    loop {
        let mut entry = std::ptr::null_mut();
        let status = unsafe { acl_get_entry(acl.0, entry_id, &mut entry) };
        if status != 0 {
            return if status == -1
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL)
            {
                Ok(())
            } else {
                Err(error("unavailable"))
            };
        }
        entry_id = -1;
        if entry.is_null() {
            return Err(error("unavailable"));
        }
        let mut tag = 0;
        if unsafe { acl_get_tag_type(entry, &mut tag) } != 0 {
            return Err(error("unavailable"));
        }
        match tag {
            2 => continue,
            1 => (),
            _ => return Err(error("unavailable")),
        }
        let mut flags = std::ptr::null_mut();
        if unsafe { acl_get_flagset_np(entry, &mut flags) } != 0 || flags.is_null() {
            return Err(error("unavailable"));
        }
        for inherited in [1 << 5, 1 << 6, 1 << 7, 1 << 8] {
            if unsafe { acl_get_flag_np(flags, inherited) } != 0 {
                return Err(error("unavailable"));
            }
        }
        let qualifier = Acl::new(unsafe { acl_get_qualifier(entry) })?;
        let mut owner = [0u8; 16];
        if unsafe { mbr_uid_to_uuid(libc::geteuid(), owner.as_mut_ptr()) } != 0 {
            return Err(error("unavailable"));
        }
        let principal = unsafe { std::ptr::read_unaligned(qualifier.0.cast::<[u8; 16]>()) };
        if principal != owner {
            return Err(error("unavailable"));
        }
    }
}

unsafe extern "C" {
    fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> *mut c_void;
    fn acl_valid(acl: *mut c_void) -> libc::c_int;
    fn acl_get_entry(
        acl: *mut c_void,
        entry_id: libc::c_int,
        entry: *mut *mut c_void,
    ) -> libc::c_int;
    fn acl_get_tag_type(entry: *mut c_void, tag: *mut libc::c_int) -> libc::c_int;
    fn acl_get_flagset_np(entry: *mut c_void, flags: *mut *mut c_void) -> libc::c_int;
    fn acl_get_flag_np(flags: *mut c_void, flag: libc::c_int) -> libc::c_int;
    fn acl_get_qualifier(entry: *mut c_void) -> *mut c_void;
    fn acl_free(value: *mut c_void) -> libc::c_int;
    fn mbr_uid_to_uuid(uid: libc::uid_t, uuid: *mut u8) -> libc::c_int;
}
