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
//!     println!("Interface LUID: {:#x}", *address.interface_luid());
//!     println!("Address Family: {:?}", address.family());
//!     println!("IP Address: {:?}", address.address());
//! }
//! # Ok::<(), std::io::Error>(())
//! ```

use bitflags::bitflags;
use std::{
    ffi::{OsStr, OsString, c_void},
    io, mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::Deref,
    os::windows::{ffi::OsStringExt, io::RawHandle},
    ptr,
    sync::Mutex,
};
use windows_sys::Win32::{
    Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS, NO_ERROR},
    NetworkManagement::{
        IpHelper::{
            CancelMibChangeNotify2, ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToAlias,
            ConvertInterfaceLuidToGuid, ConvertInterfaceLuidToIndex, FreeMibTable,
            GAA_FLAG_INCLUDE_ALL_COMPARTMENTS, GAA_FLAG_INCLUDE_ALL_INTERFACES,
            GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_INCLUDE_PREFIX,
            GAA_FLAG_INCLUDE_TUNNEL_BINDINGORDER, GAA_FLAG_INCLUDE_WINS_INFO,
            GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
            GetAdaptersAddresses, GetIpForwardEntry2, GetIpForwardTable2, GetIpInterfaceEntry,
            GetUnicastIpAddressTable, IP_ADAPTER_ADDRESSES_LH, IP_ADDRESS_PREFIX,
            MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW,
            MIB_UNICASTIPADDRESS_ROW, MIB_UNICASTIPADDRESS_TABLE, MibAddInstance,
            MibDeleteInstance, MibInitialNotification, MibParameterNotification,
            NotifyIpInterfaceChange, NotifyRouteChange2, SetIpInterfaceEntry,
        },
        Ndis::{IF_MAX_STRING_SIZE, NET_LUID_LH},
    },
    Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_INET},
};
use windows_sys::core::GUID;

use crate::util::string_to_null_terminated_utf16;

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

/// A LUID (locally unique identifier) for a network interface
///
/// Can be created from or converted to a `u64` or [`NET_LUID_LH`].
///
/// [`NET_LUID_LH`]: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/net-luid-value
#[repr(transparent)]
pub struct Luid(u64);

// Ensure Luid and NET_LUID_LH have the same layout
const _: () = {
    assert!(mem::size_of::<Luid>() == mem::size_of::<NET_LUID_LH>());
    assert!(mem::align_of::<Luid>() == mem::align_of::<NET_LUID_LH>());
};

impl AsRef<Luid> for NET_LUID_LH {
    fn as_ref(&self) -> &Luid {
        // SAFETY: Luid and NET_LUID_LH have the same layout
        unsafe { &*(self as *const NET_LUID_LH as *const Luid) }
    }
}

impl AsRef<NET_LUID_LH> for Luid {
    fn as_ref(&self) -> &NET_LUID_LH {
        // SAFETY: Luid and NET_LUID_LH have the same layout
        unsafe { &*(self as *const Luid as *const NET_LUID_LH) }
    }
}

impl Deref for Luid {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<NET_LUID_LH> for Luid {
    fn from(luid: NET_LUID_LH) -> Self {
        // SAFETY: Always a valid u64
        Luid(unsafe { luid.Value })
    }
}

impl From<u64> for Luid {
    fn from(value: u64) -> Self {
        Luid(value)
    }
}

impl From<Luid> for u64 {
    fn from(luid: Luid) -> Self {
        luid.0
    }
}

impl From<Luid> for NET_LUID_LH {
    fn from(luid: Luid) -> Self {
        NET_LUID_LH { Value: luid.0 }
    }
}

/// A GUID (global unique identifier) for a network interface
///
/// Can be created from or converted to a `u128` or [`GUID`].
///
/// [`GUID`]: https://learn.microsoft.com/en-us/windows/win32/api/guiddef/ns-guiddef-guid
pub struct Guid(GUID);

impl From<GUID> for Guid {
    fn from(guid: GUID) -> Self {
        Guid(guid)
    }
}

impl From<u128> for Guid {
    fn from(guid: u128) -> Self {
        Guid(GUID::from_u128(guid))
    }
}

impl From<Guid> for GUID {
    fn from(value: Guid) -> Self {
        value.0
    }
}

// Ensure Guid, GUID, and u128 have the same layout
const _: () = {
    assert!(mem::size_of::<Guid>() == mem::size_of::<GUID>());
    assert!(mem::align_of::<Guid>() == mem::align_of::<GUID>());
    assert!(mem::size_of::<Guid>() == mem::size_of::<u128>());
    // NOTE: alignment differs:
    //assert!(mem::align_of::<Guid>() == mem::align_of::<u128>());
};

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

    // SAFETY: table is valid for `num_entries` entries
    let entries = unsafe { std::slice::from_raw_parts((*table).Table.as_ptr(), num_entries) }
        .iter()
        .map(|&raw_entry| UnicastIpAddressRow { raw_entry })
        .collect();

    // SAFETY: All entries are plain old data, and we have copied them
    unsafe {
        FreeMibTable(table as *mut _);
    }

    Ok(entries)
}

/// Retrieve the IP forward table for a specific address family
///
/// If `family` is `None` (AF_UNSPEC), all address families will be retrieved.
///
/// This uses the [`GetIpForwardTable2`] Windows API function.
///
/// # Example
///
/// ```no_run
/// use dos::net::get_ip_forward_table;
///
/// // Get all routes in the system
/// for route in get_ip_forward_table(None)? {
///     let (dest, prefix_len) = route.destination_prefix();
///     println!("Route: {}/{} -> {} (metric: {})",
///              dest, prefix_len, route.next_hop(), route.metric());
/// }
/// # Ok::<(), std::io::Error>(())
/// ```
///
/// [`GetIpForwardTable2`]: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipforwardtable2
pub fn get_ip_forward_table(family: Option<AddressFamily>) -> io::Result<Vec<RouteRow>> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = ptr::null_mut();

    let family = family.map(|f| f as u16).unwrap_or(AF_UNSPEC);

    // SAFETY: `table` is valid to be written to
    let result = unsafe { GetIpForwardTable2(family, &mut table) };

    if result != NO_ERROR {
        return Err(io::Error::from_raw_os_error(result as i32));
    }

    debug_assert_ne!(table, ptr::null_mut());

    // SAFETY: table is valid and points to a MIB_IPFORWARD_TABLE2
    let num_entries = usize::try_from(unsafe { (*table).NumEntries }).unwrap();

    // SAFETY: table is valid for `num_entries` entries
    let entries = unsafe { std::slice::from_raw_parts((*table).Table.as_ptr(), num_entries) }
        .iter()
        .map(|&row| RouteRow { row })
        .collect();

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
    pub fn interface_luid(&self) -> Luid {
        Luid::from(self.raw_entry.InterfaceLuid)
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
    Luid(Luid),
    /// Interface index
    Index(u32),
}

impl<T: Into<Luid>> From<T> for InterfaceIdentifier {
    fn from(luid: T) -> Self {
        InterfaceIdentifier::Luid(luid.into())
    }
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

/// Get a route entry by destination prefix and interface.
///
/// This uses the [`GetIpForwardEntry2`] Windows API function.
///
/// # Arguments
///
/// * `interface` - The interface identifier (LUID or index)
/// * `destination_prefix` - The destination prefix IP address and length
/// * `next_hop` - The next hop IP address
///
/// # Example
///
/// ```no_run
/// use dos::net::{get_ip_forward_entry, InterfaceIdentifier};
/// use std::net::Ipv4Addr;
///
/// // Get the default route (0.0.0.0/0) on interface index 1
/// let route = get_ip_forward_entry(
///     InterfaceIdentifier::Index(1),
///     (Ipv4Addr::UNSPECIFIED.into(), 0),
///     Ipv4Addr::UNSPECIFIED.into(),
/// )?;
///
/// println!("Route metric: {}", route.metric());
/// println!("Next hop: {}", route.next_hop());
/// # Ok::<(), std::io::Error>(())
/// ```
///
/// [`GetIpForwardEntry2`]: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipforwardentry2
pub fn get_ip_forward_entry(
    interface: impl Into<InterfaceIdentifier>,
    destination_prefix: (IpAddr, u8),
    next_hop: IpAddr,
) -> io::Result<RouteRow> {
    match interface.into() {
        InterfaceIdentifier::Luid(luid) => {
            RouteRow::get_by_destination_and_interface(destination_prefix, luid, next_hop)
        }
        InterfaceIdentifier::Index(index) => {
            RouteRow::get_by_destination_and_index(destination_prefix, index, next_hop)
        }
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
    fn get_by_luid(luid: impl Into<Luid>, family: AddressFamily) -> io::Result<Self> {
        Self::get_inner(|| MIB_IPINTERFACE_ROW {
            Family: family as u16,
            InterfaceLuid: NET_LUID_LH::from(luid.into()),
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
    pub fn interface_luid(&self) -> Luid {
        Luid::from(self.row.InterfaceLuid)
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

impl<'a> From<&'a MIB_IPINTERFACE_ROW> for &'a IpInterfaceRow {
    fn from(row: &'a MIB_IPINTERFACE_ROW) -> Self {
        IpInterfaceRow::new(row)
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

        let result = set_ip_interface_entry(&self);

        self.row.SitePrefixLength = prev_prefix_len;

        result
    }
}

impl AsRef<MIB_IPINTERFACE_ROW> for IpInterfaceRowModifier {
    fn as_ref(&self) -> &MIB_IPINTERFACE_ROW {
        &self.row
    }
}

/// A single IP route entry in the system routing table.
///
/// This is a wrapper around [`MIB_IPFORWARD_ROW2`].
///
/// [`MIB_IPFORWARD_ROW2`]: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipforward_row2
#[repr(transparent)]
pub struct RouteRow {
    row: MIB_IPFORWARD_ROW2,
}

impl RouteRow {
    /// Create a new `RouteRow` from a raw `row`, without taking ownership
    pub fn new(row: &MIB_IPFORWARD_ROW2) -> &Self {
        let pprows = row as *const MIB_IPFORWARD_ROW2;
        // SAFETY: row is a valid row, and we preserve its lifetime
        // Since `RouteRow` is transparent, we may simply cast it
        unsafe { &*(pprows.cast()) }
    }

    /// Get a route entry by destination prefix and interface.
    ///
    /// This uses the [`GetIpForwardEntry2`] Windows API function.
    ///
    /// [`GetIpForwardEntry2`]: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipforwardentry2
    fn get_by_destination_and_interface(
        destination_prefix: (IpAddr, u8),
        interface_luid: impl Into<Luid>,
        next_hop: IpAddr,
    ) -> io::Result<Self> {
        let interface_luid = interface_luid.into();

        Self::get_inner(|| MIB_IPFORWARD_ROW2 {
            InterfaceLuid: NET_LUID_LH::from(interface_luid),
            DestinationPrefix: IP_ADDRESS_PREFIX {
                Prefix: Self::prefix_from_ip(destination_prefix.0),
                PrefixLength: destination_prefix.1,
            },
            NextHop: Self::prefix_from_ip(next_hop),
            ..Default::default()
        })
    }

    /// Get a route entry by destination prefix and interface index.
    ///
    /// This uses the [`GetIpForwardEntry2`] Windows API function.
    ///
    /// [`GetIpForwardEntry2`]: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipforwardentry2
    fn get_by_destination_and_index(
        destination_prefix: (IpAddr, u8),
        interface_index: u32,
        next_hop: IpAddr,
    ) -> io::Result<Self> {
        Self::get_inner(|| MIB_IPFORWARD_ROW2 {
            InterfaceIndex: interface_index,
            DestinationPrefix: IP_ADDRESS_PREFIX {
                Prefix: Self::prefix_from_ip(destination_prefix.0),
                PrefixLength: destination_prefix.1,
            },
            NextHop: Self::prefix_from_ip(next_hop),
            ..Default::default()
        })
    }

    fn prefix_from_ip(ip: IpAddr) -> SOCKADDR_INET {
        let mut addr = SOCKADDR_INET::default();
        match ip {
            IpAddr::V4(ipv4) => {
                addr.si_family = AF_INET;
                addr.Ipv4.sin_addr.S_un.S_addr = u32::from_be_bytes(ipv4.octets());
            }
            IpAddr::V6(ipv6) => {
                addr.si_family = AF_INET6;
                addr.Ipv6.sin6_addr.u.Byte = ipv6.octets();
            }
        }
        addr
    }

    fn get_inner(make_row: impl FnOnce() -> MIB_IPFORWARD_ROW2) -> io::Result<Self> {
        let mut row = make_row();

        // SAFETY: `row` is initialized
        let status = unsafe { GetIpForwardEntry2(&mut row) };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }

        Ok(RouteRow { row })
    }

    /// Get the destination prefix for this route, as (address, prefix length)
    ///
    /// Return `None` if the address family is not recognized.
    pub fn destination_prefix(&self) -> (IpAddr, u8) {
        // SAFETY: The union is valid
        let dest = unsafe {
            match self.row.DestinationPrefix.Prefix.si_family {
                AF_INET => {
                    let addr = self.row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr;
                    IpAddr::V4(Ipv4Addr::from(u32::from_be(addr)))
                }
                AF_INET6 => {
                    let addr = self.row.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte;
                    IpAddr::V6(Ipv6Addr::from(addr))
                }
                // TODO: Is this reachable?
                _ => unreachable!("invalid address family"),
            }
        };
        (dest, self.prefix_length())
    }

    /// Get the prefix length for this route
    fn prefix_length(&self) -> u8 {
        self.row.DestinationPrefix.PrefixLength
    }

    /// Get the next hop address for this route
    ///
    /// Return `None` if the address family is not recognized.
    pub fn next_hop(&self) -> IpAddr {
        // SAFETY: The union is valid
        unsafe {
            match self.row.NextHop.si_family {
                AF_INET => {
                    let addr = self.row.NextHop.Ipv4.sin_addr.S_un.S_addr;
                    IpAddr::V4(Ipv4Addr::from(u32::from_be(addr)))
                }
                AF_INET6 => {
                    let addr = self.row.NextHop.Ipv6.sin6_addr.u.Byte;
                    IpAddr::V6(Ipv6Addr::from(addr))
                }
                // TODO: Is this reachable?
                _ => unreachable!("invalid address family"),
            }
        }
    }

    /// Get the interface index for this route
    pub fn interface_index(&self) -> u32 {
        self.row.InterfaceIndex
    }

    /// Get the interface LUID for this route
    pub fn interface_luid(&self) -> Luid {
        Luid::from(self.row.InterfaceLuid)
    }

    /// Get the route metric
    pub fn metric(&self) -> u32 {
        self.row.Metric
    }

    /// Get whether this is an immortal route
    pub fn immortal(&self) -> bool {
        self.row.Immortal
    }

    /// Get the age of the route in seconds
    pub fn age(&self) -> u32 {
        self.row.Age
    }

    /// Get the raw route row structure
    pub fn as_raw(&self) -> &MIB_IPFORWARD_ROW2 {
        &self.row
    }
}

impl<'a> From<&'a MIB_IPFORWARD_ROW2> for &'a RouteRow {
    fn from(raw: &'a MIB_IPFORWARD_ROW2) -> Self {
        RouteRow::new(raw)
    }
}

impl AsRef<MIB_IPFORWARD_ROW2> for RouteRow {
    fn as_ref(&self) -> &MIB_IPFORWARD_ROW2 {
        &self.row
    }
}

/// Notification type for change callbacks
///
/// Corresponds to `MIB_NOTIFICATION_TYPE` in the Windows API.
pub enum NotificationType<'a, T> {
    /// A parameter of an existing instance has changed.
    ParameterNotification(&'a T),
    /// A new instance has been added.
    AddInstance(&'a T),
    /// An existing instance has been deleted.
    DeleteInstance(&'a T),
    /// Initial notification to confirm registration of callback.
    InitialNotification,
}

impl<T> From<&NotificationType<'_, T>> for i32 {
    fn from(nt: &NotificationType<'_, T>) -> Self {
        match nt {
            NotificationType::ParameterNotification(_) => MibParameterNotification,
            NotificationType::AddInstance(_) => MibAddInstance,
            NotificationType::DeleteInstance(_) => MibDeleteInstance,
            NotificationType::InitialNotification => MibInitialNotification,
        }
    }
}

/// Callback for `notify_*` functions
pub trait NotificationCb<T>: FnMut(NotificationType<'_, T>) + Send {}

impl<T, F: FnMut(NotificationType<'_, T>) + Send> NotificationCb<T> for F {}

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
/// # Example
///
/// ```no_run
/// use dos::net::{notify_ip_interface_change, NotificationType};
/// use std::{thread, time::Duration};
///
/// // Register for interface change notifications
/// let _handle = notify_ip_interface_change(
///     None,
///     |notification_type| {
///         match notification_type {
///             NotificationType::InitialNotification => {
///                 println!("Monitoring started");
///             }
///             NotificationType::AddInstance(interface) => {
///                 println!("Interface added: Family {:?}", interface.family());
///             }
///             NotificationType::DeleteInstance(interface) => {
///                 println!("Interface removed: Family {:?}", interface.family());
///             }
///             NotificationType::ParameterNotification(interface) => {
///                 println!("Interface changed: Family {:?}", interface.family());
///             }
///         }
///     },
///     true, // Request initial notification
/// )?;
///
/// # Ok::<(), std::io::Error>(())
/// ```
///
/// [`NotifyIpInterfaceChange`]: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-notifyipinterfacechange
pub fn notify_ip_interface_change(
    family: Option<AddressFamily>,
    callback: impl NotificationCb<IpInterfaceRow> + 'static,
    initial_notification: bool,
) -> io::Result<Box<NotifyCallbackHandle<IpInterfaceRow>>> {
    let mut context = Box::new(NotifyCallbackHandle {
        callback: Mutex::new(Box::new(callback)),
        handle: ptr::null_mut(),
    });

    // SAFETY: context is valid until the callback is unregistered
    let status = unsafe {
        NotifyIpInterfaceChange(
            family.map(|f| f as u16).unwrap_or(AF_UNSPEC),
            Some(notify_callback::<MIB_IPINTERFACE_ROW, IpInterfaceRow>),
            &mut *context.as_mut() as *mut _ as *mut _,
            initial_notification,
            (&mut context.handle) as *mut _,
        )
    };

    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }

    Ok(context)
}

/// Handle returned by `notify_ip_interface_change`. When dropped, the callback is unregistered
/// and monitoring stops.
pub struct NotifyCallbackHandle<T> {
    callback: Mutex<Box<dyn NotificationCb<T>>>,
    handle: RawHandle,
}

unsafe impl<T> Send for NotifyCallbackHandle<T> {}

impl<T> Drop for NotifyCallbackHandle<T> {
    fn drop(&mut self) {
        // SAFETY: handle is valid
        unsafe { CancelMibChangeNotify2(self.handle) };
    }
}

#[allow(non_upper_case_globals)]
unsafe extern "system" fn notify_callback<'a, UnderlyingType: 'a, WrappedType: 'a>(
    context: *const c_void,
    row: *const UnderlyingType,
    notification_type: i32,
) where
    &'a WrappedType: From<&'a UnderlyingType>,
{
    if context.is_null() {
        return;
    }

    // SAFETY: context and row are valid pointers
    let context = unsafe { &*(context as *mut NotifyCallbackHandle<WrappedType>) };
    let mut callback = context.callback.lock().unwrap();

    if notification_type == MibInitialNotification {
        (callback)(NotificationType::InitialNotification);
        return;
    }

    // SAFETY: `row` is never null for any other notification type
    let raw = unsafe { &*row };
    let converted: &WrappedType = <&WrappedType>::from(raw);

    match notification_type {
        MibParameterNotification => {
            (callback)(NotificationType::ParameterNotification(converted));
        }
        MibAddInstance => {
            (callback)(NotificationType::AddInstance(converted));
        }
        MibDeleteInstance => {
            (callback)(NotificationType::DeleteInstance(converted));
        }
        other => unreachable!("invalid notification type: {other}"),
    }
}

/// Registers a callback function that is invoked when a route is added, removed, or changed.
///
/// On success, this returns a notification handle. The callback is unregistered and monitoring
/// stops when the handle is dropped.
///
/// This uses the [`NotifyRouteChange2`] Windows API function.
///
/// # Arguments
///
/// - `family`: The address family to monitor. If `None`, all address families are monitored.
/// - `callback`: The callback function to invoke when a route change occurs.
/// - `initial_notification`: Whether to immediately invoke the callback to confirm
///   registration of callback.
///
/// # Example
///
/// ```no_run
/// use dos::net::{notify_route_change, NotificationType};
/// use std::{thread, time::Duration};
///
/// // Register for route change notifications
/// let _handle = notify_route_change(
///     None, // Monitor all address families
///     |notification_type| {
///         match notification_type {
///             NotificationType::InitialNotification => {
///                 println!("Route monitoring started");
///             }
///             NotificationType::AddInstance(route) => {
///                 println!("Route added: {:?} -> {:?}",
///                          route.destination_prefix(), route.next_hop());
///             }
///             NotificationType::DeleteInstance(route) => {
///                 println!("Route removed: {:?}", route.destination_prefix());
///             }
///             NotificationType::ParameterNotification(route) => {
///                 println!("Route changed: {:?} (metric: {})",
///                          route.destination_prefix(), route.metric());
///             }
///         }
///     },
///     true, // Request initial notification
/// )?;
///
/// // Keep the handle alive to continue monitoring
/// thread::sleep(Duration::from_secs(60));
/// # Ok::<(), std::io::Error>(())
/// ```
///
/// [`NotifyRouteChange2`]: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-notifyroutechange2
pub fn notify_route_change(
    family: Option<AddressFamily>,
    callback: impl NotificationCb<RouteRow> + 'static,
    initial_notification: bool,
) -> io::Result<Box<NotifyCallbackHandle<RouteRow>>> {
    let mut context = Box::new(NotifyCallbackHandle {
        callback: Mutex::new(Box::new(callback)),
        handle: ptr::null_mut(),
    });

    // SAFETY: context is valid until the callback is unregistered
    let status = unsafe {
        NotifyRouteChange2(
            family.map(|f| f as u16).unwrap_or(AF_UNSPEC),
            Some(notify_callback::<MIB_IPFORWARD_ROW2, RouteRow>),
            &mut *context.as_mut() as *mut _ as *mut _,
            initial_notification,
            (&mut context.handle) as *mut _,
        )
    };

    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }

    Ok(context)
}

/// Return the network interface index given its [Luid].
///
/// This uses the [`ConvertInterfaceLuidToIndex`] Windows API function.
///
/// [`ConvertInterfaceLuidToIndex`]: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-convertinterfaceluidtoindex
pub fn convert_interface_luid_to_index(luid: impl Into<Luid>) -> io::Result<u32> {
    let mut index = 0u32;
    let luid = luid.into();

    // SAFETY: `index` is valid to be written to
    let status = unsafe { ConvertInterfaceLuidToIndex(luid.as_ref(), &mut index) };
    if status != NO_ERROR {
        return Err(io::Error::from_raw_os_error(status as i32));
    }

    Ok(index)
}

/// Return the [Guid] of a network interface given its [Luid].
///
/// This uses the [`ConvertInterfaceLuidToGuid`] Windows API function.
///
/// [`ConvertInterfaceLuidToGuid`]: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-convertinterfaceluidtoguid
pub fn convert_interface_luid_to_guid(luid: impl Into<Luid>) -> io::Result<Guid> {
    let mut guid = GUID::default();
    let luid = luid.into();

    // SAFETY: `guid` is a valid pointer to a GUID
    let status = unsafe { ConvertInterfaceLuidToGuid(luid.as_ref(), &mut guid) };
    if status != NO_ERROR {
        return Err(io::Error::from_raw_os_error(status as i32));
    }

    Ok(guid.into())
}

/// Return the [Luid] of a network interface given its alias.
///
/// This uses the [`ConvertInterfaceAliasToLuid`] Windows API function.
///
/// [`ConvertInterfaceAliasToLuid`]: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-convertinterfacealiastoluid
pub fn convert_interface_alias_to_luid<T: AsRef<OsStr>>(alias: T) -> io::Result<Luid> {
    let alias_wide: Vec<u16> = string_to_null_terminated_utf16(alias);
    let mut luid = NET_LUID_LH::default();

    // SAFETY: `alias_wide` is a valid null-terminated wide string, and `luid` is a valid buffer
    let status = unsafe { ConvertInterfaceAliasToLuid(alias_wide.as_ptr(), &mut luid) };
    if status != NO_ERROR {
        return Err(io::Error::from_raw_os_error(status as i32));
    }

    Ok(luid.into())
}

/// Return the alias of a network interface given its [Luid].
///
/// This uses the [`ConvertInterfaceLuidToAlias`] Windows API function.
///
/// [`ConvertInterfaceLuidToAlias`]: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-convertinterfaceluidtoalias
pub fn convert_interface_luid_to_alias(luid: impl Into<Luid>) -> io::Result<OsString> {
    let mut buffer = [0u16; IF_MAX_STRING_SIZE as usize + 1];
    let luid = luid.into();

    let status =
        unsafe { ConvertInterfaceLuidToAlias(luid.as_ref(), buffer.as_mut_ptr(), buffer.len()) };
    if status != NO_ERROR {
        return Err(io::Error::from_raw_os_error(status as i32));
    }

    let nul = buffer.iter().position(|&c| c == 0u16).unwrap();
    Ok(OsString::from_wide(&buffer[0..nul]))
}

bitflags! {
    /// Flags for [`get_adapters_addresses`] specifying what information to include.
    ///
    /// These correspond to the `GAA_FLAG_*` constants from the Windows API.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct AdapterAddressFlags: u32 {
        // TODO: missing flags
        /// Include prefix information for IP addresses
        const INCLUDE_PREFIX = GAA_FLAG_INCLUDE_PREFIX;
        /// Skip anycast addresses
        const SKIP_ANYCAST = GAA_FLAG_SKIP_ANYCAST;
        /// Skip multicast addresses
        const SKIP_MULTICAST = GAA_FLAG_SKIP_MULTICAST;
        /// Skip DNS server addresses
        const SKIP_DNS_SERVER = GAA_FLAG_SKIP_DNS_SERVER;
        /// Include WINS server information
        const INCLUDE_WINS_INFO = GAA_FLAG_INCLUDE_WINS_INFO;
        /// Include gateway addresses
        const INCLUDE_GATEWAYS = GAA_FLAG_INCLUDE_GATEWAYS;
        /// Include all interfaces, even those not bound to specified address family
        const INCLUDE_ALL_INTERFACES = GAA_FLAG_INCLUDE_ALL_INTERFACES;
        /// Include all network compartments
        const INCLUDE_ALL_COMPARTMENTS = GAA_FLAG_INCLUDE_ALL_COMPARTMENTS;
        /// Include tunnel binding order
        const INCLUDE_TUNNEL_BINDINGORDER = GAA_FLAG_INCLUDE_TUNNEL_BINDINGORDER;
    }
}

/// Retrieve the addresses associated with the adapters on the local computer.
///
/// This function calls the Windows [`GetAdaptersAddresses`] API to get detailed information
/// about network adapters, including their addresses, names, and configuration.
///
/// # Arguments
///
/// * `family` - The address family to retrieve. If `None`, both IPv4 and IPv6 are retrieved.
/// * `flags` - Flags that control what information is retrieved.
///
/// # Returns
///
/// Returns an [`AdapterAddressTable`] containing all the adapter information.
///
/// # Example
///
/// ```no_run
/// use dos::net::{get_adapters_addresses, AdapterAddressFlags};
///
/// // Get all adapters with basic information
/// let adapters = get_adapters_addresses(None, AdapterAddressFlags::empty())?;
/// for adapter in &adapters {
///     println!("Adapter: {}", adapter.friendly_name().to_string_lossy());
///     println!("  Description: {}", adapter.description().to_string_lossy());
///     println!("  MTU: {}", adapter.mtu());
/// }
/// # Ok::<(), std::io::Error>(())
/// ```
///
/// [`GetAdaptersAddresses`]: https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses
pub fn get_adapters_addresses(
    family: Option<AddressFamily>,
    flags: AdapterAddressFlags,
) -> io::Result<AdapterAddressTable> {
    let family = family.map(|f| f as u16).unwrap_or(AF_UNSPEC);
    let mut size: u32 = 15 * 1024;
    let mut buffer = vec![0u8; size as usize];

    loop {
        // SAFETY: `buffer` is valid and `size` is the size of the buffer
        let result = unsafe {
            GetAdaptersAddresses(
                u32::from(family),
                flags.bits(),
                ptr::null_mut(),
                buffer.as_mut_ptr() as *mut _,
                &mut size,
            )
        };

        if result == ERROR_BUFFER_OVERFLOW {
            buffer.resize(size as usize, 0);
            continue;
        }
        if result != NO_ERROR {
            return Err(io::Error::from_raw_os_error(result as i32));
        }

        break;
    }

    // Resize buffer to actual used size
    buffer.truncate(size as usize);

    Ok(AdapterAddressTable { buffer })
}

/// A collection of network adapter information retrieved from [`GetAdaptersAddresses`].
///
/// This struct owns the raw data returned by the Windows API and provides an iterator
/// over the adapter entries.
///
/// [`GetAdaptersAddresses`]: https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses
pub struct AdapterAddressTable {
    buffer: Vec<u8>,
}

impl AdapterAddressTable {
    /// Return an iterator over the adapter addresses in this table
    pub fn iter(&self) -> AdapterAddressIterator<'_> {
        AdapterAddressIterator {
            current: if self.buffer.is_empty() {
                ptr::null()
            } else {
                self.buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH
            },
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<'a> IntoIterator for &'a AdapterAddressTable {
    type Item = AdapterAddress<'a>;
    type IntoIter = AdapterAddressIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterator over adapter addresses in an [`AdapterAddressTable`]
pub struct AdapterAddressIterator<'a> {
    current: *const IP_ADAPTER_ADDRESSES_LH,
    _phantom: std::marker::PhantomData<&'a IP_ADAPTER_ADDRESSES_LH>,
}

impl<'a> Iterator for AdapterAddressIterator<'a> {
    type Item = AdapterAddress<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current.is_null() {
            return None;
        }

        // SAFETY: current is valid and points to an IP_ADAPTER_ADDRESSES_LH structure
        let adapter = unsafe { &*self.current };
        let result = AdapterAddress { raw: adapter };

        // Move to the next adapter
        self.current = adapter.Next;

        Some(result)
    }
}

/// A single network adapter address entry from [`AdapterAddressTable`]
///
/// This corresponds to an [`IP_ADAPTER_ADDRESSES_LH`] structure from the Windows API.
///
/// [`IP_ADAPTER_ADDRESSES_LH`]: https://learn.microsoft.com/en-us/windows/win32/api/iptypes/ns-iptypes-ip_adapter_addresses_lh
pub struct AdapterAddress<'a> {
    raw: &'a IP_ADAPTER_ADDRESSES_LH,
}

impl<'a> AdapterAddress<'a> {
    /// Get the adapter name
    ///
    /// This corresponds to the `AdapterName` field in `IP_ADAPTER_ADDRESSES_LH`.
    pub fn adapter_name(&self) -> &str {
        // SAFETY: AdapterName is a null-terminated string
        unsafe {
            std::ffi::CStr::from_ptr(self.raw.AdapterName as *const i8)
                .to_str()
                .unwrap_or("<invalid>")
        }
    }

    /// Get the friendly name of the adapter
    ///
    /// This corresponds to the `FriendlyName` field in `IP_ADAPTER_ADDRESSES_LH`.
    pub fn friendly_name(&self) -> OsString {
        // SAFETY: FriendlyName is a null-terminated wide string
        unsafe { crate::util::osstring_from_wide(self.raw.FriendlyName) }
    }

    /// Get the description of the adapter
    ///
    /// This corresponds to the `Description` field in `IP_ADAPTER_ADDRESSES_LH`.
    pub fn description(&self) -> OsString {
        // SAFETY: Description is a null-terminated wide string
        unsafe { crate::util::osstring_from_wide(self.raw.Description) }
    }

    /// Get the adapter interface LUID
    ///
    /// This corresponds to the `Luid` field in `IP_ADAPTER_ADDRESSES_LH`.
    pub fn interface_luid(&self) -> Luid {
        self.raw.Luid.into()
    }

    /// Get the MTU size for this adapter
    ///
    /// This corresponds to the `Mtu` field in `IP_ADAPTER_ADDRESSES_LH`.
    pub fn mtu(&self) -> u32 {
        self.raw.Mtu
    }

    /// Get the raw adapter addresses structure
    pub fn as_raw(&self) -> &IP_ADAPTER_ADDRESSES_LH {
        self.raw
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
