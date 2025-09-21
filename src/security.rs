//! Security and access control functionality
//!
//! # Examples
//!
//! Get security information for a file:
//!
//! ```no_run
//! use dos::security::{SecurityInformation, ObjectType, get_security_info};
//! use std::fs::File;
//! use std::os::windows::io::AsRawHandle;
//!
//! let file = File::open("example.txt")?;
//! let security_info = get_security_info(
//!     &file,
//!     ObjectType::File,
//!     SecurityInformation::OWNER | SecurityInformation::GROUP
//! )?;
//!
//! if let Some(owner) = security_info.owner() {
//!     println!("File owner SID found");
//! }
//!
//! if let Some(group) = security_info.group() {
//!     println!("File group SID found");
//! }
//! # Ok::<(), std::io::Error>(())
//! ```

use bitflags::bitflags;
use std::{
    ffi::{OsStr, c_void},
    io,
    ops::Deref,
    os::windows::{ffi::OsStrExt, io::AsRawHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{ERROR_SUCCESS, LocalFree},
    Security::{
        ACL,
        Authorization::{
            GetNamedSecurityInfoW, GetSecurityInfo, SE_FILE_OBJECT, SE_KERNEL_OBJECT, SE_LMSHARE,
            SE_PRINTER, SE_REGISTRY_KEY, SE_SERVICE, SE_UNKNOWN_OBJECT_TYPE, SE_WINDOW_OBJECT,
            SE_WMIGUID_OBJECT,
        },
        DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, IsWellKnownSid,
        OWNER_SECURITY_INFORMATION, PSID, SACL_SECURITY_INFORMATION, SECURITY_DESCRIPTOR,
        SECURITY_MAX_SID_SIZE, WinAnonymousSid, WinAuthenticatedUserSid, WinBatchSid,
        WinBuiltinAccountOperatorsSid, WinBuiltinAdministratorsSid, WinBuiltinBackupOperatorsSid,
        WinBuiltinDomainSid, WinBuiltinGuestsSid, WinBuiltinPowerUsersSid,
        WinBuiltinPrintOperatorsSid, WinBuiltinReplicatorSid, WinBuiltinSystemOperatorsSid,
        WinBuiltinUsersSid, WinCreatorGroupSid, WinCreatorOwnerSid, WinDialupSid,
        WinEnterpriseControllersSid, WinInteractiveSid, WinLocalServiceSid, WinLocalSid,
        WinLocalSystemSid, WinNetworkServiceSid, WinNetworkSid, WinNtAuthoritySid, WinNullSid,
        WinProxySid, WinRemoteLogonIdSid, WinRestrictedCodeSid, WinSelfSid, WinServiceSid,
        WinTerminalServerSid, WinWorldSid,
    },
};

/// Object types for security operations
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectType {
    /// Unknown object type
    Unknown = SE_UNKNOWN_OBJECT_TYPE,
    /// File or directory
    File = SE_FILE_OBJECT,
    /// Service
    Service = SE_SERVICE,
    /// Printer
    Printer = SE_PRINTER,
    /// Registry key
    RegistryKey = SE_REGISTRY_KEY,
    /// Network share
    LmShare = SE_LMSHARE,
    /// Kernel object
    KernelObject = SE_KERNEL_OBJECT,
    /// Window object
    WindowObject = SE_WINDOW_OBJECT,
    /// WMI GUID object
    WmiGuidObject = SE_WMIGUID_OBJECT,
}

bitflags! {
    /// Security information flags for specifying which parts of security descriptor to retrieve
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct SecurityInformation: u32 {
        /// Owner security information
        const OWNER = OWNER_SECURITY_INFORMATION;
        /// Group security information
        const GROUP = GROUP_SECURITY_INFORMATION;
        /// Discretionary access control list (DACL) security information
        const DACL = DACL_SECURITY_INFORMATION;
        /// System access control list (SACL) security information
        const SACL = SACL_SECURITY_INFORMATION;
    }
}

/// Get security information for an object.
///
/// This calls the underlying [`GetSecurityInfo`] Windows API function.
///
/// [`GetSecurityInfo`]: https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo
pub fn get_security_info<T: AsRawHandle>(
    handle: &T,
    object_type: ObjectType,
    info: SecurityInformation,
) -> io::Result<SecurityInfo> {
    SecurityInfo::from_handle(handle, object_type, info)
}

/// Get security information for an object specified by name.
///
/// This calls the underlying [`GetNamedSecurityInfoW`] Windows API function.
///
/// [`GetNamedSecurityInfoW`]: https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getnamedsecurityinfow
pub fn get_named_security_info(
    name: impl AsRef<OsStr>,
    object_type: ObjectType,
    info: SecurityInformation,
) -> io::Result<SecurityInfo> {
    SecurityInfo::from_name(name, object_type, info)
}

/// Copy of a security descriptor for an object
pub struct SecurityInfo {
    /// Owner SID
    owner: Option<&'static Sid>,
    /// Group SID  
    group: Option<&'static Sid>,
    /// Discretionary ACL
    // TODO
    //dacl: Option<*mut ACL>,
    /// System ACL
    // TODO
    //sacl: Option<*mut ACL>,
    /// Raw security descriptor
    security_descriptor: *mut SECURITY_DESCRIPTOR,
}

impl SecurityInfo {
    /// Get security information for an object.
    ///
    /// This calls the underlying [`GetSecurityInfo`] Windows API function.
    ///
    /// [`GetSecurityInfo`]: https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo
    fn from_handle<T: AsRawHandle>(
        handle: &T,
        object_type: ObjectType,
        info: SecurityInformation,
    ) -> io::Result<SecurityInfo> {
        Self::new_inner(|owner_ptr, group_ptr, dacl_ptr, sacl_ptr, sd_ptr| {
            // SAFETY: `handle` is a valid handle, as are all pointers
            unsafe {
                GetSecurityInfo(
                    handle.as_raw_handle(),
                    object_type as i32,
                    info.bits(),
                    owner_ptr,
                    group_ptr,
                    dacl_ptr,
                    sacl_ptr,
                    sd_ptr as *mut *mut c_void,
                )
            }
        })
    }

    /// Get security information for an object specified by name.
    ///
    /// This calls the underlying [`GetNamedSecurityInfoW`] Windows API function.
    ///
    /// [`GetNamedSecurityInfoW`]: https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getnamedsecurityinfow
    fn from_name(
        name: impl AsRef<OsStr>,
        object_type: ObjectType,
        info: SecurityInformation,
    ) -> io::Result<SecurityInfo> {
        let name_wide: Vec<u16> = name
            .as_ref()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        Self::new_inner(|owner_ptr, group_ptr, dacl_ptr, sacl_ptr, sd_ptr| {
            // SAFETY: `name_wide` is a valid null-terminated wide string, as are all pointers
            unsafe {
                GetNamedSecurityInfoW(
                    name_wide.as_ptr(),
                    object_type as i32,
                    info.bits(),
                    owner_ptr,
                    group_ptr,
                    dacl_ptr,
                    sacl_ptr,
                    sd_ptr as *mut *mut c_void,
                )
            }
        })
    }

    fn new_inner(
        make_descriptor: impl FnOnce(
            *mut PSID,
            *mut PSID,
            *mut *mut ACL,
            *mut *mut ACL,
            *mut *mut SECURITY_DESCRIPTOR,
        ) -> u32,
    ) -> io::Result<Self> {
        let mut security_descriptor: *mut SECURITY_DESCRIPTOR = ptr::null_mut();
        let mut owner: PSID = ptr::null_mut();
        let mut group: PSID = ptr::null_mut();
        let mut dacl: *mut ACL = ptr::null_mut();
        let mut sacl: *mut ACL = ptr::null_mut();

        // SAFETY: All pointers are valid pointers to pointers
        let result = make_descriptor(
            &mut owner,
            &mut group,
            &mut dacl,
            &mut sacl,
            &mut security_descriptor,
        );

        if result != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(result as i32));
        }

        let _ = dacl;
        let _ = sacl;

        Ok(SecurityInfo {
            owner: if owner.is_null() {
                None
            } else {
                // SAFETY: `owner` is valid for lifetime of `self`
                Some(unsafe { Sid::new(owner) })
            },
            group: if group.is_null() {
                None
            } else {
                // SAFETY: `group` is valid for lifetime of `self`
                Some(unsafe { Sid::new(group) })
            },
            // TODO
            //dacl: if dacl.is_null() { None } else { Some(dacl) },
            // TODO
            //sacl: if sacl.is_null() { None } else { Some(sacl) },
            security_descriptor,
        })
    }

    /// Returns the owner SID, if present
    pub fn owner(&self) -> Option<&Sid> {
        self.owner
    }

    /// Returns the group SID, if present
    pub fn group(&self) -> Option<&Sid> {
        self.group
    }
}

impl Drop for SecurityInfo {
    fn drop(&mut self) {
        // SAFETY: This is a valid security descriptor
        unsafe { LocalFree(self.security_descriptor.cast()) };
    }
}

/// Well-known security identifier (SID) types
///
/// These correspond to the `WELL_KNOWN_SID_TYPE` enumeration from the Windows API.
// TODO: check accuracy
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WellKnownSidType {
    /// Null SID
    Null = WinNullSid,
    /// Everyone group (S-1-1-0)
    World = WinWorldSid,
    /// Local users (S-1-2-0)
    Local = WinLocalSid,
    /// Creator owner (S-1-3-0)
    CreatorOwner = WinCreatorOwnerSid,
    /// Creator group (S-1-3-1)
    CreatorGroup = WinCreatorGroupSid,
    /// NT Authority (S-1-5)
    NtAuthority = WinNtAuthoritySid,
    /// Dialup users (S-1-5-1)
    Dialup = WinDialupSid,
    /// Network users (S-1-5-2)
    Network = WinNetworkSid,
    /// Batch process (S-1-5-3)
    Batch = WinBatchSid,
    /// Interactive users (S-1-5-4)
    Interactive = WinInteractiveSid,
    /// Service accounts (S-1-5-6)
    Service = WinServiceSid,
    /// Anonymous logon (S-1-5-7)
    Anonymous = WinAnonymousSid,
    /// Proxy (S-1-5-8)
    Proxy = WinProxySid,
    /// Enterprise domain controllers (S-1-5-9)
    EnterpriseDomainControllers = WinEnterpriseControllersSid,
    /// Self (S-1-5-10)
    Principal = WinSelfSid,
    /// Authenticated users (S-1-5-11)
    AuthenticatedUser = WinAuthenticatedUserSid,
    /// Restricted code (S-1-5-12)
    RestrictedCode = WinRestrictedCodeSid,
    /// Terminal server users (S-1-5-13)
    TerminalServer = WinTerminalServerSid,
    /// Remote interactive logon (S-1-5-14)
    RemoteLogonId = WinRemoteLogonIdSid,
    /// Local system (S-1-5-18)
    LocalSystem = WinLocalSystemSid,
    /// Local service (S-1-5-19)
    LocalService = WinLocalServiceSid,
    /// Network service (S-1-5-20)
    NetworkService = WinNetworkServiceSid,
    /// Built-in domain (S-1-5-32)
    BuiltinDomain = WinBuiltinDomainSid,
    /// Built-in administrators (S-1-5-32-544)
    BuiltinAdministrators = WinBuiltinAdministratorsSid,
    /// Built-in users (S-1-5-32-545)
    BuiltinUsers = WinBuiltinUsersSid,
    /// Built-in guests (S-1-5-32-546)
    BuiltinGuests = WinBuiltinGuestsSid,
    /// Built-in power users (S-1-5-32-547)
    BuiltinPowerUsers = WinBuiltinPowerUsersSid,
    /// Built-in account operators (S-1-5-32-548)
    BuiltinAccountOperators = WinBuiltinAccountOperatorsSid,
    /// Built-in system operators (S-1-5-32-549)
    BuiltinSystemOperators = WinBuiltinSystemOperatorsSid,
    /// Built-in print operators (S-1-5-32-550)
    BuiltinPrintOperators = WinBuiltinPrintOperatorsSid,
    /// Built-in backup operators (S-1-5-32-551)
    BuiltinBackupOperators = WinBuiltinBackupOperatorsSid,
    /// Built-in replicators (S-1-5-32-552)
    BuiltinReplicator = WinBuiltinReplicatorSid,
}

/// A security identifier (SID)
#[repr(transparent)]
pub struct Sid {
    sid: PSID,
}

impl Sid {
    /// Create a new `Sid` from a raw `PSID`, without taking ownership
    ///
    /// # Safety
    ///
    /// The caller must ensure that the `sid` pointer is valid for the lifetime of the `Sid`
    /// instance.
    pub unsafe fn new<'a>(sid: PSID) -> &'a Self {
        let ppsid = &sid as *const PSID;
        // SAFETY: The buffer contains a valid SID.
        // Since `Sid` is transparent, we may simply cast it
        unsafe { &*(ppsid.cast()) }
    }

    /// Check if this SID matches a specific well-known SID type
    ///
    /// This calls the underlying [`IsWellKnownSid`] Windows API function.
    ///
    /// [`IsWellKnownSid`]: https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-iswellknownsid
    pub fn is_well_known_sid(&self, sid_type: WellKnownSidType) -> bool {
        // SAFETY: `self.sid` is a valid PSID
        unsafe { IsWellKnownSid(self.sid, sid_type as i32) != 0 }
    }
}

impl AsRawHandle for Sid {
    fn as_raw_handle(&self) -> *mut c_void {
        self.sid
    }
}

/// Create a well-known SID
///
/// This calls the underlying [`CreateWellKnownSid`] Windows API function.
///
/// [`CreateWellKnownSid`]: https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createwellknownsid
pub fn create_well_known_sid(sid_type: WellKnownSidType) -> io::Result<OwnedSid> {
    OwnedSid::create_well_known(sid_type)
}

/// An owned security identifier (SID)
pub struct OwnedSid {
    sid: Vec<u8>,
}

impl OwnedSid {
    /// Create a well-known SID
    ///
    /// This calls the underlying [`CreateWellKnownSid`] Windows API function.
    ///
    /// [`CreateWellKnownSid`]: https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createwellknownsid
    fn create_well_known(sid_type: WellKnownSidType) -> io::Result<Self> {
        use windows_sys::Win32::Security::CreateWellKnownSid;

        let mut sid_size = SECURITY_MAX_SID_SIZE;
        let mut sid_buffer = vec![0u8; sid_size as usize];

        // SAFETY: sid_buffer is properly allocated and sid_size is correct
        let result = unsafe {
            CreateWellKnownSid(
                sid_type as i32,
                ptr::null_mut(),
                sid_buffer.as_mut_ptr() as PSID,
                &mut sid_size,
            )
        };

        if result == 0 {
            return Err(io::Error::last_os_error());
        }

        // Truncate to actual size
        sid_buffer.truncate(sid_size as usize);
        Ok(OwnedSid { sid: sid_buffer })
    }

    /// Create a Sid reference to this SID data
    fn as_sid(&self) -> &Sid {
        // SAFETY: The buffer contains a valid SID
        unsafe { Sid::new(self.sid.as_ptr() as PSID) }
    }
}

impl Deref for OwnedSid {
    type Target = Sid;

    fn deref(&self) -> &Self::Target {
        self.as_sid()
    }
}

#[cfg(test)]
mod tests {
    use std::os::windows::fs::OpenOptionsExt;

    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;

    use super::*;

    #[test]
    fn test_well_known_sid() {
        let admin_sid = create_well_known_sid(WellKnownSidType::BuiltinAdministrators)
            .expect("Failed to create well-known SID");

        let admin_sid_ref = admin_sid.as_sid();
        assert!(admin_sid_ref.is_well_known_sid(WellKnownSidType::BuiltinAdministrators));
        assert!(!admin_sid_ref.is_well_known_sid(WellKnownSidType::LocalSystem));
    }

    #[test]
    fn test_security_info_handle() {
        let path = std::fs::File::options()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(r"C:\Windows\Temp")
            .unwrap();

        let temp_info = get_security_info(&path, ObjectType::File, SecurityInformation::OWNER)
            .expect("Failed to get security info by name");

        let owner = temp_info.owner().unwrap();

        assert!(
            owner.is_well_known_sid(WellKnownSidType::LocalSystem)
                || owner.is_well_known_sid(WellKnownSidType::BuiltinAdministrators)
        );
    }
}
