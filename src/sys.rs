//! Get system-related information

use std::{ffi::OsString, io, os::windows::ffi::OsStringExt, path::PathBuf};

use windows_sys::Win32::{Foundation::MAX_PATH, System::SystemInformation::GetSystemDirectoryW};

/// Get the system directory path. This is typically `C:\Windows\System32`.
///
/// This corresponds to the Windows API function [`GetSystemDirectoryW`].
///
/// [`GetSystemDirectoryW`]: https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemdirectoryw
pub fn get_system_directory() -> io::Result<PathBuf> {
    let mut sysdir = [0u16; MAX_PATH as usize + 1];
    // SAFETY: We have a valid buffer and length
    let len = unsafe { GetSystemDirectoryW(sysdir.as_mut_ptr(), (sysdir.len() - 1) as u32) };
    if len == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(PathBuf::from(OsString::from_wide(
        &sysdir[0..(len as usize)],
    )))
}
