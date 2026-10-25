use std::fs::Metadata;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::MetadataExt;
use std::path::Path;
use std::ptr::{null, null_mut};

use ffi::*;

use super::{ClientError, FILE_ALL_ACCESS, error, private_windows_acl};

struct Local(PSECURITY_DESCRIPTOR);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

fn wide(value: &std::ffi::OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

unsafe fn sid_string(sid: *mut std::ffi::c_void) -> Result<String, ClientError> {
    let mut text = null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(error("unavailable"));
    }
    let mut length = 0;
    while unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    let result = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length) });
    unsafe {
        LocalFree(text.cast());
    }
    Ok(result)
}

fn user() -> Result<String, ClientError> {
    let mut token = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(error("unavailable"));
    }
    let mut length = 0;
    unsafe {
        GetTokenInformation(token, TokenUser, null_mut(), 0, &mut length);
    }
    let mut buffer = vec![0usize; (length as usize).div_ceil(std::mem::size_of::<usize>())];
    let success = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            length,
            &mut length,
        )
    };
    unsafe {
        CloseHandle(token);
    }
    if success == 0 {
        return Err(error("unavailable"));
    }
    unsafe { sid_string((*(buffer.as_ptr().cast::<TOKEN_USER>())).User.Sid) }
}

pub(super) fn state_home() -> Result<std::path::PathBuf, ClientError> {
    let initialized = unsafe { CoInitializeEx(null_mut(), 2) };
    if initialized < 0 && initialized != 0x80010106u32 as i32 {
        return Err(error("unavailable"));
    }
    let mut path = null_mut();
    let folder = GUID {
        data1: 0xf1b32785,
        data2: 0x6fba,
        data3: 0x4fcf,
        data4: [0x9d, 0x55, 0x7b, 0x8e, 0x7f, 0x15, 0x70, 0x91],
    };
    let status = unsafe { SHGetKnownFolderPath(&folder, 0, null_mut(), &mut path) };
    let result = if status < 0 || path.is_null() {
        Err(error("unavailable"))
    } else {
        let mut length = 0;
        while unsafe { *path.add(length) } != 0 {
            length += 1;
        }
        Ok(
            std::ffi::OsString::from_wide(unsafe { std::slice::from_raw_parts(path, length) })
                .into(),
        )
    };
    unsafe {
        CoTaskMemFree(path.cast());
        if initialized >= 0 {
            CoUninitialize();
        }
    }
    result
}

pub(super) fn no_reparse(metadata: &Metadata) -> Result<(), ClientError> {
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(error("unavailable"));
    }
    Ok(())
}

fn attributes() -> Result<(Local, SECURITY_ATTRIBUTES), ClientError> {
    let sid = user()?;
    let sddl = wide(std::ffi::OsStr::new(&format!(
        "O:{sid}D:P(A;OICI;FA;;;{sid})"
    )));
    let mut descriptor = null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(error("unavailable"));
    }
    let descriptor = Local(descriptor);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    Ok((descriptor, attributes))
}

pub(super) fn directory(path: &Path) -> Result<(), ClientError> {
    let (_descriptor, attributes) = attributes()?;
    let path = wide(path.as_os_str());
    if unsafe { CreateDirectoryW(path.as_ptr(), &attributes) } == 0 {
        if std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists {
            return Err(super::io_error(std::io::Error::last_os_error()));
        }
    }
    Ok(())
}

pub(super) fn create(path: &Path) -> Result<std::fs::File, ClientError> {
    use std::os::windows::io::FromRawHandle;
    let (_descriptor, attributes) = attributes()?;
    let path = wide(path.as_os_str());
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            FILE_ALL_ACCESS,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(super::io_error(std::io::Error::last_os_error()));
    }
    Ok(unsafe { std::fs::File::from_raw_handle(handle) })
}

pub(super) fn private(path: &Path, metadata: &Metadata) -> Result<(), ClientError> {
    no_reparse(metadata)?;
    let path = wide(path.as_os_str());
    if metadata.is_file() {
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(error("unavailable"));
        }
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        let success = unsafe { GetFileInformationByHandle(handle, &mut info) };
        unsafe {
            CloseHandle(handle);
        }
        if success == 0 || info.nNumberOfLinks != 1 {
            return Err(error("unavailable"));
        }
    }
    let mut owner = null_mut();
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor = null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(error("unavailable"));
    }
    let descriptor = Local(descriptor);
    let user = user()?;
    if owner.is_null() || dacl.is_null() || unsafe { sid_string(owner)? } != user {
        return Err(error("unavailable"));
    }
    let mut control = 0;
    let mut revision = 0;
    if unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) } == 0 {
        return Err(error("unavailable"));
    }
    if unsafe { (*dacl).AceCount } != 1 {
        return Err(error("unavailable"));
    }
    let mut entry = null_mut();
    if unsafe { GetAce(dacl, 0, &mut entry) } == 0 {
        return Err(error("unavailable"));
    }
    let header = unsafe { &*entry.cast::<ACE_HEADER>() };
    if header.AceType != 0 || header.AceSize < 16 {
        return Err(error("unavailable"));
    }
    let sid = unsafe { entry.cast::<u8>().add(8) };
    let sid_length = 8 + 4 * usize::from(unsafe { *sid.add(1) });
    if sid_length > usize::from(header.AceSize) - 8 {
        return Err(error("unavailable"));
    }
    let ace = unsafe { &*entry.cast::<ACCESS_ALLOWED_ACE>() };
    let sid = (&ace.SidStart as *const u32).cast_mut().cast();
    private_windows_acl(
        control,
        ace.Header.AceFlags,
        ace.Mask,
        &unsafe { sid_string(sid)? },
        &user,
    )
}

// These declarations mirror the Win32 ABI; no credential-store library is linked.
#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    clippy::upper_case_acronyms
)]
mod ffi {
    use std::ffi::c_void;
    pub type PSECURITY_DESCRIPTOR = *mut c_void;
    pub const INVALID_HANDLE_VALUE: *mut c_void = -1isize as *mut c_void;
    pub const TOKEN_QUERY: u32 = 8;
    pub const TokenUser: u32 = 1;
    pub const OWNER_SECURITY_INFORMATION: u32 = 1;
    pub const DACL_SECURITY_INFORMATION: u32 = 4;
    pub const SE_FILE_OBJECT: u32 = 1;
    pub const FILE_READ_ATTRIBUTES: u32 = 0x80;
    pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    pub const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    pub const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x00200000;
    pub const FILE_SHARE_READ: u32 = 1;
    pub const FILE_SHARE_WRITE: u32 = 2;
    pub const FILE_SHARE_DELETE: u32 = 4;
    pub const CREATE_NEW: u32 = 1;
    pub const OPEN_EXISTING: u32 = 3;
    #[repr(C)]
    pub struct SECURITY_ATTRIBUTES {
        pub nLength: u32,
        pub lpSecurityDescriptor: *mut c_void,
        pub bInheritHandle: i32,
    }
    #[repr(C)]
    pub struct ACL {
        pub revision: u8,
        pub sbz1: u8,
        pub size: u16,
        pub AceCount: u16,
        pub sbz2: u16,
    }
    #[repr(C)]
    pub struct ACE_HEADER {
        pub AceType: u8,
        pub AceFlags: u8,
        pub AceSize: u16,
    }
    #[repr(C)]
    pub struct ACCESS_ALLOWED_ACE {
        pub Header: ACE_HEADER,
        pub Mask: u32,
        pub SidStart: u32,
    }
    #[repr(C)]
    pub struct SID_AND_ATTRIBUTES {
        pub Sid: *mut c_void,
        pub Attributes: u32,
    }
    #[repr(C)]
    pub struct TOKEN_USER {
        pub User: SID_AND_ATTRIBUTES,
    }
    #[repr(C)]
    pub struct BY_HANDLE_FILE_INFORMATION {
        pub attributes: u32,
        pub creation: [u32; 2],
        pub access: [u32; 2],
        pub write: [u32; 2],
        pub volume: u32,
        pub size: [u32; 2],
        pub nNumberOfLinks: u32,
        pub index: [u32; 2],
    }
    #[repr(C)]
    pub struct GUID {
        pub data1: u32,
        pub data2: u16,
        pub data3: u16,
        pub data4: [u8; 8],
    }
    #[link(name = "ole32")]
    unsafe extern "system" {
        pub fn CoInitializeEx(reserved: *mut c_void, flags: u32) -> i32;
        pub fn CoUninitialize();
        pub fn CoTaskMemFree(pointer: *mut c_void);
    }
    #[link(name = "shell32")]
    unsafe extern "system" {
        pub fn SHGetKnownFolderPath(
            folder: *const GUID,
            flags: u32,
            token: *mut c_void,
            path: *mut *mut u16,
        ) -> i32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        pub fn GetCurrentProcess() -> *mut c_void;
        pub fn CloseHandle(handle: *mut c_void) -> i32;
        pub fn LocalFree(pointer: *mut c_void) -> *mut c_void;
        pub fn CreateDirectoryW(path: *const u16, attributes: *const SECURITY_ATTRIBUTES) -> i32;
        pub fn CreateFileW(
            path: *const u16,
            access: u32,
            share: u32,
            attributes: *const SECURITY_ATTRIBUTES,
            disposition: u32,
            flags: u32,
            template: *mut c_void,
        ) -> *mut c_void;
        pub fn GetFileInformationByHandle(
            handle: *mut c_void,
            info: *mut BY_HANDLE_FILE_INFORMATION,
        ) -> i32;
    }
    #[link(name = "advapi32")]
    unsafe extern "system" {
        pub fn OpenProcessToken(process: *mut c_void, access: u32, token: *mut *mut c_void) -> i32;
        pub fn GetTokenInformation(
            token: *mut c_void,
            class: u32,
            info: *mut c_void,
            length: u32,
            returned: *mut u32,
        ) -> i32;
        pub fn ConvertSidToStringSidW(sid: *mut c_void, text: *mut *mut u16) -> i32;
        pub fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text: *const u16,
            revision: u32,
            descriptor: *mut PSECURITY_DESCRIPTOR,
            size: *mut u32,
        ) -> i32;
        pub fn GetNamedSecurityInfoW(
            path: *const u16,
            ty: u32,
            security: u32,
            owner: *mut *mut c_void,
            group: *mut *mut c_void,
            dacl: *mut *mut ACL,
            sacl: *mut *mut ACL,
            descriptor: *mut PSECURITY_DESCRIPTOR,
        ) -> u32;
        pub fn GetSecurityDescriptorControl(
            descriptor: PSECURITY_DESCRIPTOR,
            control: *mut u16,
            revision: *mut u32,
        ) -> i32;
        pub fn GetAce(acl: *const ACL, index: u32, ace: *mut *mut c_void) -> i32;
    }
}
