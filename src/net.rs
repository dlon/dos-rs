//! Network-related functionality
//!
//! # Examples
//!
//! Get all unicast IP addresses on the system:
//!
//! ```no_run
//! use dos::net::get_unicast_ip_address_table;
//!
//! for address in get_unicast_ip_address_table(None)? {
//!     println!("Interface Index: {}", address.interface_index());
//!     println!("Interface LUID: {:#x}", address.interface_luid());
//!     println!("Address Family: {:?}", address.family());
//!     println!("IP Address: {:?}", address.address());
//! }
//! # Ok::<(), std::io::Error>(())
//! ```

use std::{
    ffi::c_void,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::windows::io::RawHandle,
    ptr,
    sync::Mutex,
};
use windows_sys::Win32::{
    Foundation::{ERROR_SUCCESS, NO_ERROR},
    NetworkManagement::{
        IpHelper::{
            CancelMibChangeNotify2, FreeMibTable, GetIpInterfaceEntry, GetUnicastIpAddressTable,
            MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW, MIB_UNICASTIPADDRESS_TABLE,
            MibAddInstance, MibDeleteInstance, MibInitialNotification, MibParameterNotification,
            NotifyIpInterfaceChange, SetIpInterfaceEntry,
        },
        Ndis::NET_LUID_LH,
    },
    Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC},
};

/// Address family for IP addresses
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressFamily {
    /// IPv4 address family
    Inet = AF_INET as isize,
    /// IPv6 address family
    Inet6 = AF_INET6 as isize,
}

impl TryFrom<u16> for AddressFamily {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            AF_INET => Ok(AddressFamily::Inet),
            AF_INET6 => Ok(AddressFamily::Inet6),
            _ => Err(()),
        }
    }
}

/// Retrieve the unicast IP address table for a specific address family
///
/// If `family` is `None` (AF_UNSPEC), all address families will be retrieved.
///
/// This uses the [`GetUnicastIpAddressTable`] Windows API function.
///
/// [`GetUnicastIpAddressTable`]: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getunicastipaddresstable
pub fn get_unicast_ip_address_table(
    family: Option<AddressFamily>,
) -> io::Result<Vec<UnicastIpAddressRow>> {
    let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = ptr::null_mut();

    let family = family.map(|f| f as u16).unwrap_or(AF_UNSPEC);

    // SAFETY: `table` is valid to be written to
    let result = unsafe { GetUnicastIpAddressTable(family, &mut table) };

    if result != NO_ERROR {
        return Err(io::Error::from_raw_os_error(result as i32));
    }

    debug_assert_ne!(table, ptr::null_mut());

    // SAFETY: table is valid and points to a MIB_UNICASTIPADDRESS_TABLE
    let num_entries = usize::try_from(unsafe { (*table).NumEntries }).unwrap();
    let mut entries = Vec::with_capacity(num_entries);

    for i in 0..num_entries {
        // SAFETY: We've verified the index is within bounds
        let raw_entry = unsafe {
            let entries_ptr = (*table).Table.as_ptr();
            *entries_ptr.add(i)
        };
        entries.push(UnicastIpAddressRow { raw_entry });
    }

    // SAFETY: All entries are plain old data, and we have copied them
    unsafe {
        FreeMibTable(table as *mut _);
    }

    Ok(entries)
}

/// A unicast IP address entry from the system's IP address table
///
/// This corresponds to a [`MIB_UNICASTIPADDRESS_ROW`] structure from the Windows API.
///
/// [`MIB_UNICASTIPADDRESS_ROW`]: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_unicastipaddress_row
#[repr(transparent)]
pub struct UnicastIpAddressRow {
    raw_entry: MIB_UNICASTIPADDRESS_ROW,
}

impl UnicastIpAddressRow {
    /// Get the network interface index
    pub fn interface_index(&self) -> u32 {
        self.raw_entry.InterfaceIndex
    }

    /// Get the address family
    pub fn family(&self) -> AddressFamily {
        // SAFETY: si_family is always initialized
        unsafe { AddressFamily::try_from(self.raw_entry.Address.si_family) }
            .expect("invalid address family")
    }

    /// Get the interface LUID
    pub fn interface_luid(&self) -> u64 {
        // SAFETY: Always a valid u64
        unsafe { self.raw_entry.InterfaceLuid.Value }
    }

    /// Get the IP address
    pub fn address(&self) -> IpAddr {
        match self.family() {
            AddressFamily::Inet => {
                // SAFETY: We've verified this is an IPv4 address
                let addr_bytes = unsafe { self.raw_entry.Address.Ipv4.sin_addr.S_un.S_addr };
                let ipv4 = Ipv4Addr::from(addr_bytes.to_ne_bytes());
                IpAddr::V4(ipv4)
            }
            AddressFamily::Inet6 => {
                // SAFETY: We've verified this is an IPv6 address
                let addr_bytes = unsafe { self.raw_entry.Address.Ipv6.sin6_addr.u.Byte };
                let ipv6 = Ipv6Addr::from(addr_bytes);
                IpAddr::V6(ipv6)
            }
        }
    }

    /// Get the prefix length
    pub fn prefix_length(&self) -> u8 {
        match self.raw_entry.OnLinkPrefixLength {
            prefix @ 0..=128 => prefix,
            _ if self.family() == AddressFamily::Inet => 32,
            _ if self.family() == AddressFamily::Inet6 => 128,
            _ => panic!("invalid prefix length"),
        }
    }

    /// Get the raw `MIB_UNICASTIPADDRESS_ROW` structure
    pub fn as_raw(&self) -> &MIB_UNICASTIPADDRESS_ROW {
        &self.raw_entry
    }
}

/// Identifier for a network interface
pub enum InterfaceIdentifier {
    /// Interface LUID
    Luid(u64),
    /// Interface index
    Index(u32),
}

/// Get an interface entry by LUID and address family.
///
/// This uses the [`GetIpInterfaceEntry`] Windows API function.
///
/// [`GetIpInterfaceEntry`]: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipinterfaceentry
pub fn get_ip_interface_entry(
    id: impl Into<InterfaceIdentifier>,
    family: AddressFamily,
) -> io::Result<IpInterfaceRow> {
    match id.into() {
        InterfaceIdentifier::Luid(luid) => IpInterfaceRow::get_by_luid(luid, family),
        InterfaceIdentifier::Index(index) => IpInterfaceRow::get_by_index(index, family),
    }
}

/// Set an interface entry. The interface is identified by LUID or index.
///
/// This uses the [`SetIpInterfaceEntry`] Windows API function.
///
/// Note that `SitePrefixLength` must be cleared when setting the entry, at least for IPv4.
///
/// [`SetIpInterfaceEntry`]: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-setipinterfaceentry
pub fn set_ip_interface_entry(interface: impl AsRef<MIB_IPINTERFACE_ROW>) -> io::Result<()> {
    let interface = interface.as_ref();

    // SAFETY: `interface` is initialized, and SetIpInterfaceEntry does not actually modify data
    let status = unsafe { SetIpInterfaceEntry(interface as *const _ as *mut _) };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }

    Ok(())
}

impl From<NET_LUID_LH> for InterfaceIdentifier {
    fn from(luid: NET_LUID_LH) -> Self {
        // SAFETY: Always a valid u64
        InterfaceIdentifier::Luid(unsafe { luid.Value })
    }
}

/// A network interface entry
///
/// This corresponds to a [`MIB_IPINTERFACE_ROW`] structure from the Windows API.
///
/// [`MIB_IPINTERFACE_ROW`]: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipinterface_row
#[repr(transparent)]
pub struct IpInterfaceRow {
    row: MIB_IPINTERFACE_ROW,
}

impl IpInterfaceRow {
    /// Create a new `IpInterfaceRow` from a raw `row`, without taking ownership
    pub fn new(row: &MIB_IPINTERFACE_ROW) -> &Self {
        let pprows = row as *const MIB_IPINTERFACE_ROW;
        // SAFETY: row is a valid row, and we preserve its lifetime
        // Since `IpInterfaceRow` is transparent, we may simply cast it
        unsafe { &*(pprows.cast()) }
    }

    /// Get an interface entry by index and address family.
    ///
    /// This uses the [`GetIpInterfaceEntry`] Windows API function.
    ///
    /// [`GetIpInterfaceEntry`]: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipinterfaceentry
    fn get_by_index(index: u32, family: AddressFamily) -> io::Result<Self> {
        Self::get_inner(|| MIB_IPINTERFACE_ROW {
            Family: family as u16,
            InterfaceIndex: index,
            ..Default::default()
        })
    }

    /// Get an interface entry by LUID and address family.
    ///
    /// This uses the [`GetIpInterfaceEntry`] Windows API function.
    ///
    /// [`GetIpInterfaceEntry`]: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipinterfaceentry
    fn get_by_luid(luid: u64, family: AddressFamily) -> io::Result<Self> {
        Self::get_inner(|| MIB_IPINTERFACE_ROW {
            Family: family as u16,
            InterfaceLuid: NET_LUID_LH { Value: luid },
            ..Default::default()
        })
    }

    fn get_inner(make_row: impl FnOnce() -> MIB_IPINTERFACE_ROW) -> io::Result<Self> {
        let mut row = make_row();

        // SAFETY: `row` is initialized
        let status = unsafe { GetIpInterfaceEntry(&mut row) };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }

        Ok(IpInterfaceRow { row })
    }

    /// Get the interface LUID
    ///
    /// Corresponds to the `InterfaceLuid` field in `MIB_IPINTERFACE_ROW`.
    pub fn interface_luid(&self) -> u64 {
        // SAFETY: Always a valid u64
        unsafe { self.row.InterfaceLuid.Value }
    }

    /// Get the address family
    ///
    /// Corresponds to the `Family` field in `MIB_IPINTERFACE_ROW`.
    pub fn family(&self) -> AddressFamily {
        AddressFamily::try_from(self.row.Family).expect("invalid address family")
    }

    /// Get the interface metric
    ///
    /// Corresponds to the `Metric` field in `MIB_IPINTERFACE_ROW`.
    pub fn metric(&self) -> u32 {
        self.row.Metric
    }

    /// Get whether automatic metric is enabled
    ///
    /// Corresponds to the `UseAutomaticMetric` field in `MIB_IPINTERFACE_ROW`.
    pub fn automatic_metric(&self) -> bool {
        self.row.UseAutomaticMetric
    }

    /// Get the interface MTU
    ///
    /// Corresponds to the `NlMtu` field in `MIB_IPINTERFACE_ROW`.
    pub fn mtu(&self) -> u32 {
        self.row.NlMtu
    }

    /// Create a convenience builder to modify this interface entry
    pub fn modify(self) -> IpInterfaceRowModifier {
        IpInterfaceRowModifier { row: self.row }
    }

    /// Get the raw `MIB_IPINTERFACE_ROW` structure
    pub fn as_raw(&self) -> &MIB_IPINTERFACE_ROW {
        &self.row
    }

    /// Get a mutable reference to the raw `MIB_IPINTERFACE_ROW` structure
    pub fn as_raw_mut(&mut self) -> &mut MIB_IPINTERFACE_ROW {
        &mut self.row
    }
}

impl AsRef<MIB_IPINTERFACE_ROW> for IpInterfaceRow {
    fn as_ref(&self) -> &MIB_IPINTERFACE_ROW {
        &self.row
    }
}

/// Modifier for network adapter interfaces
///
/// On save, this calls the [`SetIpInterfaceEntry`] Windows API function.
///
/// [`SetIpInterfaceEntry`]: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-setipinterfaceentry
pub struct IpInterfaceRowModifier {
    row: MIB_IPINTERFACE_ROW,
}

impl IpInterfaceRowModifier {
    /// Set the interface metric
    ///
    /// Corresponds to the `Metric` field in `MIB_IPINTERFACE_ROW`. Note that this also
    /// sets `UseAutomaticMetric` to false.
    pub fn set_metric(mut self, metric: u32) -> Self {
        self.row.Metric = metric;
        self.row.UseAutomaticMetric = false;
        self
    }

    /// Enable or disable automatic metric
    ///
    /// Corresponds to the `UseAutomaticMetric` field in `MIB_IPINTERFACE_ROW`.
    pub fn set_automatic_metric(mut self, enabled: bool) -> Self {
        self.row.UseAutomaticMetric = enabled;
        self
    }

    /// Set the interface MTU
    ///
    /// Corresponds to the `NlMtu` field in `MIB_IPINTERFACE_ROW`.
    pub fn set_mtu(mut self, mtu: u32) -> Self {
        self.row.NlMtu = mtu;
        self
    }

    /// Modify the raw `MIB_IPINTERFACE_ROW` structure
    pub fn as_raw_mut(&mut self) -> &mut MIB_IPINTERFACE_ROW {
        &mut self.row
    }

    /// Apply changes to the system
    ///
    /// This calls [`set_ip_interface_entry`].
    pub fn save(mut self) -> io::Result<()> {
        // Temporarily clear SitePrefixLength to avoid errors
        // See docs: It must be zeroed, at least for IPv4.
        let prev_prefix_len = self.row.SitePrefixLength;
        self.row.SitePrefixLength = 0;

        set_ip_interface_entry(&self)?;

        self.row.SitePrefixLength = prev_prefix_len;

        Ok(())
    }
}

impl AsRef<MIB_IPINTERFACE_ROW> for IpInterfaceRowModifier {
    fn as_ref(&self) -> &MIB_IPINTERFACE_ROW {
        &self.row
    }
}

pub enum NotificationType<'a> {
    /// A parameter of an existing instance has changed.
    ParameterNotification(&'a IpInterfaceRow),
    /// A new instance has been added.
    AddInstance(&'a IpInterfaceRow),
    /// An existing instance has been deleted.
    DeleteInstance(&'a IpInterfaceRow),
    /// Initial notification to confirm registration of callback.
    InitialNotification,
}

impl From<&NotificationType<'_>> for i32 {
    fn from(nt: &NotificationType<'_>) -> Self {
        match nt {
            NotificationType::ParameterNotification(_) => MibParameterNotification,
            NotificationType::AddInstance(_) => MibAddInstance,
            NotificationType::DeleteInstance(_) => MibDeleteInstance,
            NotificationType::InitialNotification => MibInitialNotification,
        }
    }
}

/// Callback for `notify_ip_interface_change`
pub trait NotifyIpInterfaceChangeCb: FnMut(NotificationType<'_>) {}

impl<T: FnMut(NotificationType<'_>)> NotifyIpInterfaceChangeCb for T {}

/// Registers a callback function that is invoked when an interface is added, removed, or changed.
///
/// On success, this returns a notification handle. The callback is unregistered and monitoring
/// stops when the handle is dropped.
///
/// This uses the [`NotifyIpInterfaceChange`] Windows API function.
///
/// # Arguments
///
/// - `family`: The address family to monitor. If `None`, all address families are monitored.
/// - `callback`: The callback function to invoke when an interface change occurs.
/// - `initial_notification`: Whether to immediately invoke the callback to confirm
///   registration of callback.
///
/// # Safety
///
/// The callback must be Send, as it may be called from another thread.
///
/// `NotifyIpInterfaceChange` serializes calls, but not for different families, so it must also hide
/// its internal state behind a mutex.
///
/// [`NotifyIpInterfaceChange`]: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-notifyipinterfacechange
pub fn notify_ip_interface_change<'a, T: NotifyIpInterfaceChangeCb + Send + 'a>(
    family: Option<AddressFamily>,
    callback: T,
    initial_notification: bool,
) -> io::Result<Box<IpInterfaceChangeHandle<'a>>> {
    let mut context = Box::new(IpInterfaceChangeHandle {
        callback: Mutex::new(Box::new(callback)),
        handle: ptr::null_mut(),
    });

    let status = unsafe {
        NotifyIpInterfaceChange(
            family.map(|f| f as u16).unwrap_or(AF_UNSPEC),
            Some(notify_ip_interface_change_callback),
            &mut *context.as_mut() as *mut _ as *mut _,
            initial_notification,
            (&mut context.handle) as *mut _,
        )
    };

    if status != ERROR_SUCCESS {
        return Err(io::Error::last_os_error());
    }

    Ok(context)
}

/// Handle returned by `notify_ip_interface_change`. When dropped, the callback is unregistered
/// and monitoring stops.
pub struct IpInterfaceChangeHandle<'a> {
    callback: Mutex<Box<dyn NotifyIpInterfaceChangeCb + Send + 'a>>,
    handle: RawHandle,
}

unsafe impl Send for IpInterfaceChangeHandle<'_> {}

impl Drop for IpInterfaceChangeHandle<'_> {
    fn drop(&mut self) {
        // SAFETY: handle is valid
        unsafe { CancelMibChangeNotify2(self.handle) };
    }
}

#[allow(non_upper_case_globals)]
unsafe extern "system" fn notify_ip_interface_change_callback(
    context: *const c_void,
    row: *const MIB_IPINTERFACE_ROW,
    notification_type: i32,
) {
    if context.is_null() {
        return;
    }

    // SAFETY: context and row are valid pointers
    let context = unsafe { &*(context as *mut IpInterfaceChangeHandle) };
    let mut callback = context.callback.lock().unwrap();

    if notification_type == MibInitialNotification {
        (callback)(NotificationType::InitialNotification);
        return;
    }

    // SAFETY: `row` is never null for any other notification type
    let row = unsafe { &*row };
    let ip_row = IpInterfaceRow::new(row);

    match notification_type {
        MibParameterNotification => {
            (callback)(NotificationType::ParameterNotification(ip_row));
        }
        MibAddInstance => {
            (callback)(NotificationType::AddInstance(ip_row));
        }
        MibDeleteInstance => {
            (callback)(NotificationType::DeleteInstance(ip_row));
        }
        other => unreachable!("invalid notification type: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_unicast_table() {
        let table = get_unicast_ip_address_table(None).expect("Failed to get IP address table");
        for address in table {
            println!(
                "Interface: {}, Family: {:?}",
                address.interface_index(),
                address.family()
            );
        }
    }
}
