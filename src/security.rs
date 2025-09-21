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
        SECURITY_MAX_SID_SIZE, WinAccountAdministratorSid, WinAccountCertAdminsSid,
        WinAccountCloneableControllersSid, WinAccountComputersSid, WinAccountControllersSid,
        WinAccountDefaultSystemManagedSid, WinAccountDomainAdminsSid, WinAccountDomainGuestsSid,
        WinAccountDomainUsersSid, WinAccountEnterpriseAdminsSid, WinAccountEnterpriseKeyAdminsSid,
        WinAccountGuestSid, WinAccountKeyAdminsSid, WinAccountKrbtgtSid, WinAccountPolicyAdminsSid,
        WinAccountProtectedUsersSid, WinAccountRasAndIasServersSid,
        WinAccountReadonlyControllersSid, WinAnonymousSid, WinApplicationPackageAuthoritySid,
        WinAuthenticatedUserSid, WinAuthenticationAuthorityAssertedSid,
        WinAuthenticationFreshKeyAuthSid, WinAuthenticationKeyPropertyAttestationSid,
        WinAuthenticationKeyPropertyMFASid, WinAuthenticationKeyTrustSid,
        WinAuthenticationServiceAssertedSid, WinBatchSid,
        WinBuiltinAccessControlAssistanceOperatorsSid, WinBuiltinAccountOperatorsSid,
        WinBuiltinAdministratorsSid, WinBuiltinAnyPackageSid, WinBuiltinAuthorizationAccessSid,
        WinBuiltinBackupOperatorsSid, WinBuiltinCertSvcDComAccessGroup,
        WinBuiltinCryptoOperatorsSid, WinBuiltinDCOMUsersSid,
        WinBuiltinDefaultSystemManagedGroupSid, WinBuiltinDeviceOwnersSid, WinBuiltinDomainSid,
        WinBuiltinEventLogReadersGroup, WinBuiltinGuestsSid, WinBuiltinHyperVAdminsSid,
        WinBuiltinIUsersSid, WinBuiltinIncomingForestTrustBuildersSid,
        WinBuiltinNetworkConfigurationOperatorsSid, WinBuiltinPerfLoggingUsersSid,
        WinBuiltinPerfMonitoringUsersSid, WinBuiltinPowerUsersSid,
        WinBuiltinPreWindows2000CompatibleAccessSid, WinBuiltinPrintOperatorsSid,
        WinBuiltinRDSEndpointServersSid, WinBuiltinRDSManagementServersSid,
        WinBuiltinRDSRemoteAccessServersSid, WinBuiltinRemoteDesktopUsersSid,
        WinBuiltinRemoteManagementUsersSid, WinBuiltinReplicatorSid,
        WinBuiltinStorageReplicaAdminsSid, WinBuiltinSystemOperatorsSid,
        WinBuiltinTerminalServerLicenseServersSid, WinBuiltinUsersSid,
        WinCacheablePrincipalsGroupSid, WinCapabilityAppointmentsSid, WinCapabilityContactsSid,
        WinCapabilityDocumentsLibrarySid, WinCapabilityEnterpriseAuthenticationSid,
        WinCapabilityInternetClientServerSid, WinCapabilityInternetClientSid,
        WinCapabilityMusicLibrarySid, WinCapabilityPicturesLibrarySid,
        WinCapabilityPrivateNetworkClientServerSid, WinCapabilityRemovableStorageSid,
        WinCapabilitySharedUserCertificatesSid, WinCapabilityVideosLibrarySid, WinConsoleLogonSid,
        WinCreatorGroupServerSid, WinCreatorGroupSid, WinCreatorOwnerRightsSid,
        WinCreatorOwnerServerSid, WinCreatorOwnerSid, WinDialupSid, WinDigestAuthenticationSid,
        WinEnterpriseControllersSid, WinEnterpriseReadonlyControllersSid, WinHighLabelSid,
        WinIUserSid, WinInteractiveSid, WinLocalAccountAndAdministratorSid, WinLocalAccountSid,
        WinLocalLogonSid, WinLocalServiceSid, WinLocalSid, WinLocalSystemSid, WinLogonIdsSid,
        WinLowLabelSid, WinMediumLabelSid, WinMediumPlusLabelSid, WinNTLMAuthenticationSid,
        WinNetworkServiceSid, WinNetworkSid, WinNewEnterpriseReadonlyControllersSid,
        WinNonCacheablePrincipalsGroupSid, WinNtAuthoritySid, WinNullSid, WinOtherOrganizationSid,
        WinProxySid, WinRemoteLogonIdSid, WinRestrictedCodeSid, WinSChannelAuthenticationSid,
        WinSelfSid, WinServiceSid, WinSystemLabelSid, WinTerminalServerSid,
        WinThisOrganizationCertificateSid, WinThisOrganizationSid, WinUntrustedLabelSid,
        WinUserModeDriversSid, WinWorldSid, WinWriteRestrictedCodeSid,
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
/// These correspond to the [`WELL_KNOWN_SID_TYPE`] enumeration from the Windows API.
///
/// [`WELL_KNOWN_SID_TYPE`]: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-well_known_sid_type
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WellKnownSidType {
    /// Null SID
    Null = WinNullSid,
    /// Everyone group
    World = WinWorldSid,
    /// Local users
    Local = WinLocalSid,
    /// Creator owner
    CreatorOwner = WinCreatorOwnerSid,
    /// Creator group
    CreatorGroup = WinCreatorGroupSid,
    /// Creator owner server
    CreatorOwnerServerSid = WinCreatorOwnerServerSid,
    /// Creator group server
    CreatorGroupServerSid = WinCreatorGroupServerSid,
    /// NT Authority
    NtAuthority = WinNtAuthoritySid,
    /// Dialup users
    Dialup = WinDialupSid,
    /// Network users
    Network = WinNetworkSid,
    /// Batch process
    Batch = WinBatchSid,
    /// Interactive users
    Interactive = WinInteractiveSid,
    /// Service accounts
    Service = WinServiceSid,
    /// Anonymous logon
    Anonymous = WinAnonymousSid,
    /// Proxy
    Proxy = WinProxySid,
    /// Enterprise domain controllers
    EnterpriseDomainControllers = WinEnterpriseControllersSid,
    /// Self
    Principal = WinSelfSid,
    /// Authenticated users
    AuthenticatedUser = WinAuthenticatedUserSid,
    /// Restricted code
    RestrictedCode = WinRestrictedCodeSid,
    /// Terminal server users
    TerminalServer = WinTerminalServerSid,
    /// Remote interactive logon
    RemoteLogonId = WinRemoteLogonIdSid,
    /// Login IDs
    LoginIds = WinLogonIdsSid,
    /// Local system
    LocalSystem = WinLocalSystemSid,
    /// Local service
    LocalService = WinLocalServiceSid,
    /// Network service
    NetworkService = WinNetworkServiceSid,
    /// Built-in domain
    BuiltinDomain = WinBuiltinDomainSid,
    /// Built-in administrators
    BuiltinAdministrators = WinBuiltinAdministratorsSid,
    /// Built-in users
    BuiltinUsers = WinBuiltinUsersSid,
    /// Built-in guests
    BuiltinGuests = WinBuiltinGuestsSid,
    /// Built-in power users
    BuiltinPowerUsers = WinBuiltinPowerUsersSid,
    /// Built-in account operators
    BuiltinAccountOperators = WinBuiltinAccountOperatorsSid,
    /// Built-in system operators
    BuiltinSystemOperators = WinBuiltinSystemOperatorsSid,
    /// Built-in print operators
    BuiltinPrintOperators = WinBuiltinPrintOperatorsSid,
    /// Built-in backup operators
    BuiltinBackupOperators = WinBuiltinBackupOperatorsSid,
    /// Built-in replicators
    BuiltinReplicator = WinBuiltinReplicatorSid,
    /// Built-in pre-Windows 2000 compatible access
    BuiltinPreWindows2000CompatibleAccess = WinBuiltinPreWindows2000CompatibleAccessSid,
    /// Built-in remote desktop users
    BuiltinRemoteDesktopUsers = WinBuiltinRemoteDesktopUsersSid,
    /// Built-in network configuration operators
    BuiltinNetworkConfigurationOperators = WinBuiltinNetworkConfigurationOperatorsSid,
    /// Account administrator
    AccountAdministrator = WinAccountAdministratorSid,
    /// Account guest
    AccountGuest = WinAccountGuestSid,
    /// Account Kerberos target
    AccountKrbtgt = WinAccountKrbtgtSid,
    /// Account domain administrators
    AccountDomainAdmins = WinAccountDomainAdminsSid,
    /// Account domain users
    AccountDomainUsers = WinAccountDomainUsersSid,
    /// Account domain guests
    AccountDomainGuests = WinAccountDomainGuestsSid,
    /// Account computers
    AccountComputers = WinAccountComputersSid,
    /// Account controllers
    AccountControllers = WinAccountControllersSid,
    /// Account certificate administrators
    AccountCertAdmins = WinAccountCertAdminsSid,
    // TODO: missing
    /// Account enterprise administrators
    AccountEnterpriseAdmins = WinAccountEnterpriseAdminsSid,
    /// Account policy administrators
    AccountPolicyAdmins = WinAccountPolicyAdminsSid,
    /// Account RAS and IAS servers
    AccountRasAndIasServers = WinAccountRasAndIasServersSid,
    /// NTLM authentication
    NtlmAuthentication = WinNTLMAuthenticationSid,
    /// Digest authentication
    DigestAuthentication = WinDigestAuthenticationSid,
    /// SChannel authentication
    SChannelAuthentication = WinSChannelAuthenticationSid,
    /// This organization
    ThisOrganization = WinThisOrganizationSid,
    /// Other organization
    OtherOrganization = WinOtherOrganizationSid,
    /// Built-in incoming forest trust builders
    BuiltinIncomingForestTrustBuilders = WinBuiltinIncomingForestTrustBuildersSid,
    /// Built-in performance monitoring users
    BuiltinPerfMonitoringUsers = WinBuiltinPerfMonitoringUsersSid,
    /// Built-in performance logging users
    BuiltinPerfLoggingUsers = WinBuiltinPerfLoggingUsersSid,
    /// Built-in authorization access
    BuiltinAuthorizationAccess = WinBuiltinAuthorizationAccessSid,
    /// Built-in terminal server license servers
    BuiltinTerminalServerLicenseServers = WinBuiltinTerminalServerLicenseServersSid,
    /// Built-in DCOM users
    BuiltinDcomUsers = WinBuiltinDCOMUsersSid,
    /// Built-in IIS users
    BuiltinIUsers = WinBuiltinIUsersSid,
    /// IIS user
    IUser = WinIUserSid,
    /// Built-in crypto operators
    BuiltinCryptoOperators = WinBuiltinCryptoOperatorsSid,
    /// Untrusted label
    UntrustedLabel = WinUntrustedLabelSid,
    /// Low integrity label
    LowLabel = WinLowLabelSid,
    /// Medium integrity label
    MediumLabel = WinMediumLabelSid,
    /// High integrity label
    HighLabel = WinHighLabelSid,
    /// System integrity label
    SystemLabel = WinSystemLabelSid,
    /// Write restricted code
    WriteRestrictedCode = WinWriteRestrictedCodeSid,
    /// Creator owner rights
    CreatorOwnerRights = WinCreatorOwnerRightsSid,
    /// Cacheable principals group
    CacheablePrincipalsGroup = WinCacheablePrincipalsGroupSid,
    /// Non-cacheable principals group
    NonCacheablePrincipalsGroup = WinNonCacheablePrincipalsGroupSid,
    /// Enterprise read-only controllers
    EnterpriseReadonlyControllers = WinEnterpriseReadonlyControllersSid,
    /// Account read-only controllers
    AccountReadonlyControllers = WinAccountReadonlyControllersSid,
    /// Built-in event log readers
    BuiltinEventLogReaders = WinBuiltinEventLogReadersGroup,
    /// New enterprise read-only controllers
    NewEnterpriseReadonlyControllers = WinNewEnterpriseReadonlyControllersSid,
    /// Built-in certificate service DCOM access
    BuiltinCertSvcDComAccess = WinBuiltinCertSvcDComAccessGroup,
    /// Medium plus integrity label
    MediumPlusLabel = WinMediumPlusLabelSid,
    /// Local logon
    LocalLogon = WinLocalLogonSid,
    /// Console logon
    ConsoleLogon = WinConsoleLogonSid,
    /// This organization certificate
    ThisOrganizationCertificate = WinThisOrganizationCertificateSid,
    /// Application package authority
    ApplicationPackageAuthority = WinApplicationPackageAuthoritySid,
    /// Built-in any package
    BuiltinAnyPackage = WinBuiltinAnyPackageSid,
    /// Capability internet client
    CapabilityInternetClient = WinCapabilityInternetClientSid,
    /// Capability internet client server
    CapabilityInternetClientServer = WinCapabilityInternetClientServerSid,
    /// Capability private network client server
    CapabilityPrivateNetworkClientServer = WinCapabilityPrivateNetworkClientServerSid,
    /// Capability pictures library
    CapabilityPicturesLibrary = WinCapabilityPicturesLibrarySid,
    /// Capability videos library
    CapabilityVideosLibrary = WinCapabilityVideosLibrarySid,
    /// Capability music library
    CapabilityMusicLibrary = WinCapabilityMusicLibrarySid,
    /// Capability documents library
    CapabilityDocumentsLibrary = WinCapabilityDocumentsLibrarySid,
    /// Capability shared user certificates
    CapabilitySharedUserCertificates = WinCapabilitySharedUserCertificatesSid,
    /// Capability enterprise authentication
    CapabilityEnterpriseAuthentication = WinCapabilityEnterpriseAuthenticationSid,
    /// Capability removable storage
    CapabilityRemovableStorage = WinCapabilityRemovableStorageSid,
    /// RDS remote access servers
    BuiltinRDSRemoteAccessServers = WinBuiltinRDSRemoteAccessServersSid,
    /// RDS endpoint servers
    BuiltinRDSEndpointServers = WinBuiltinRDSEndpointServersSid,
    /// RDS management servers
    BuiltinRDSManagementServers = WinBuiltinRDSManagementServersSid,
    /// User-mode drivers
    UserModeDrivers = WinUserModeDriversSid,
    /// Built-in Hyper-V administrators
    BuiltinHyperVAdmins = WinBuiltinHyperVAdminsSid,
    /// Account cloneable controllers
    AccountCloneableControllers = WinAccountCloneableControllersSid,
    /// Built-in access control assistance operators
    BuiltinAccessControlAssistanceOperators = WinBuiltinAccessControlAssistanceOperatorsSid,
    /// Built-in remote management users
    BuiltinRemoteManagementUsers = WinBuiltinRemoteManagementUsersSid,
    /// Authentication authority asserted
    AuthenticationAuthorityAsserted = WinAuthenticationAuthorityAssertedSid,
    /// Authentication service asserted
    AuthenticationServiceAsserted = WinAuthenticationServiceAssertedSid,
    /// Local account
    LocalAccount = WinLocalAccountSid,
    /// Local account and administrator
    LocalAccountAndAdministrator = WinLocalAccountAndAdministratorSid,
    /// Account protected users
    AccountProtectedUsers = WinAccountProtectedUsersSid,
    /// Capability appointments
    CapabilityAppointments = WinCapabilityAppointmentsSid,
    /// Capability contacts
    CapabilityContacts = WinCapabilityContactsSid,
    /// Account default system managed
    AccountDefaultSystemManaged = WinAccountDefaultSystemManagedSid,
    /// Built-in default system managed group
    BuiltinDefaultSystemManagedGroup = WinBuiltinDefaultSystemManagedGroupSid,
    /// Built-in storage replica administrators
    BuiltinStorageReplicaAdmins = WinBuiltinStorageReplicaAdminsSid,
    /// Account key administrators
    AccountKeyAdmins = WinAccountKeyAdminsSid,
    /// Account enterprise key administrators
    AccountEnterpriseKeyAdmins = WinAccountEnterpriseKeyAdminsSid,
    /// Authentication key trust
    AuthenticationKeyTrust = WinAuthenticationKeyTrustSid,
    /// Authentication key property MFA
    AuthenticationKeyPropertyMFA = WinAuthenticationKeyPropertyMFASid,
    /// Authentication key property attestation
    AuthenticationKeyPropertyAttestation = WinAuthenticationKeyPropertyAttestationSid,
    /// Authentication fresh key authentication
    AuthenticationFreshKeyAuth = WinAuthenticationFreshKeyAuthSid,
    /// Built-in device owners
    BuiltinDeviceOwners = WinBuiltinDeviceOwnersSid,
    //BuiltinUserModeHardwareOperators = WinBuiltinUserModeHardwareOperatorsSid,
    //BuiltinOpenSSHUsers = WinBuiltinOpenSSHUsersSid,
}

/// Check if this SID matches a specific well-known SID type
///
/// This calls the underlying [`IsWellKnownSid`] Windows API function.
///
/// [`IsWellKnownSid`]: https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-iswellknownsid
pub fn is_well_known_sid(sid: &Sid, sid_type: WellKnownSidType) -> bool {
    sid.is_well_known_sid(sid_type)
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
