//! Network-related functionality
//!
//! # Examples
//!
//! Get all unicast IP addresses on the system:
//!
//! ```no_run
//! use dos::net::UnicastIpAddressTable;
//!
//! for address in UnicastIpAddressTable::all()? {
//!     println!("Interface Index: {}", address.interface_index());
//!     println!("Interface LUID: {:#x}", address.interface_luid());
//!     println!("Address Family: {:?}", address.family());
//!     println!("IP Address: {:?}", address.address());
//! }
//! # Ok::<(), std::io::Error>(())
//! ```

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr,
};
use windows_sys::Win32::{
    Foundation::NO_ERROR,
    NetworkManagement::IpHelper::{
        FreeMibTable, GetIpInterfaceEntry, GetUnicastIpAddressTable, MIB_IPINTERFACE_ROW,
        MIB_UNICASTIPADDRESS_ROW, MIB_UNICASTIPADDRESS_TABLE, SetIpInterfaceEntry,
    },
    NetworkManagement::Ndis::NET_LUID_LH,
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

/// A unicast IP address entry from the system's IP address table
///
/// This corresponds to a [`MIB_UNICASTIPADDRESS_ROW`] structure from the Windows API.
///
/// [`MIB_UNICASTIPADDRESS_ROW`]: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_unicastipaddress_row
#[repr(transparent)]
pub struct UnicastIpAddressEntry {
    raw_entry: MIB_UNICASTIPADDRESS_ROW,
}

impl UnicastIpAddressEntry {
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
}

/// Table of unicast IP addresses on the system
///
/// This uses the [`GetUnicastIpAddressTable`] Windows API function.
///
/// [`GetUnicastIpAddressTable`]: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getunicastipaddresstable
pub struct UnicastIpAddressTable {
    entries: Vec<UnicastIpAddressEntry>,
}

impl UnicastIpAddressTable {
    /// Retrieve the unicast IP address table for all address families
    pub fn all() -> io::Result<Self> {
        Self::get_for_family(None)
    }

    /// Retrieve the unicast IP address table for a specific address family
    ///
    /// If `family` is `None`, all address families will be retrieved.
    pub fn get_for_family(family: Option<AddressFamily>) -> io::Result<Self> {
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
            entries.push(UnicastIpAddressEntry { raw_entry });
        }

        // SAFETY: All entries are plain old data, and we have copied them
        unsafe {
            FreeMibTable(table as *mut _);
        }

        Ok(UnicastIpAddressTable { entries })
    }

    /// Get the number of entries in the table
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the table is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get an iterator over the IP address entries
    pub fn iter(&self) -> impl Iterator<Item = &UnicastIpAddressEntry> {
        self.entries.iter()
    }

    /// Get a specific entry by index
    pub fn get(&self, index: usize) -> Option<&UnicastIpAddressEntry> {
        self.entries.get(index)
    }
}

impl IntoIterator for UnicastIpAddressTable {
    type Item = UnicastIpAddressEntry;
    type IntoIter = std::vec::IntoIter<UnicastIpAddressEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

impl<'a> IntoIterator for &'a UnicastIpAddressTable {
    type Item = &'a UnicastIpAddressEntry;
    type IntoIter = std::slice::Iter<'a, UnicastIpAddressEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}

/// A network interface entry
///
/// This corresponds to a [`MIB_IPINTERFACE_ROW`] structure from the Windows API.
///
/// [`MIB_IPINTERFACE_ROW`]: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipinterface_row
#[repr(transparent)]
pub struct InterfaceEntry {
    row: MIB_IPINTERFACE_ROW,
}

impl InterfaceEntry {
    /// Get an interface entry by LUID and address family.
    ///
    /// This uses the [`GetIpInterfaceEntry`] Windows API function.
    ///
    /// [`GetIpInterfaceEntry`]: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipinterfaceentry
    pub fn get(luid: u64, family: AddressFamily) -> io::Result<Self> {
        let luid = NET_LUID_LH { Value: luid };
        let family = family as u16;

        let mut row = MIB_IPINTERFACE_ROW {
            InterfaceLuid: luid,
            Family: family,
            ..Default::default()
        };

        // SAFETY: `row` is initialized and has luid set
        let status = unsafe { GetIpInterfaceEntry(&mut row) };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }

        Ok(InterfaceEntry { row })
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

    /// Create a builder to modify this interface entry
    pub fn modify(self) -> InterfaceEntryModifier {
        InterfaceEntryModifier { row: self.row }
    }
}

/// Modifier for network adapter interfaces
///
/// On save, this calls the [`SetIpInterfaceEntry`] Windows API function.
///
/// [`SetIpInterfaceEntry`]: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-setipinterfaceentry
pub struct InterfaceEntryModifier {
    row: MIB_IPINTERFACE_ROW,
}

impl InterfaceEntryModifier {
    /// Create a builder for an interface entry by LUID and address family
    pub fn new(luid: u64, family: AddressFamily) -> io::Result<Self> {
        let entry = InterfaceEntry::get(luid, family)?;
        Ok(entry.modify())
    }

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
    pub fn raw_edit(mut self, modifier_fn: impl FnOnce(&mut MIB_IPINTERFACE_ROW)) -> Self {
        modifier_fn(&mut self.row);
        self
    }

    /// Apply changes to the system
    ///
    /// This calls the [`SetIpInterfaceEntry`] Windows API function.
    ///
    /// [`SetIpInterfaceEntry`]: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-setipinterfaceentry
    pub fn save(mut self) -> io::Result<()> {
        // Temporarily clear SitePrefixLength to avoid errors
        // See docs: It must be zeroed, at least for IPv4.
        let prev_prefix_len = self.row.SitePrefixLength;
        self.row.SitePrefixLength = 0;

        // SAFETY: `raw` is initialized
        let status = unsafe { SetIpInterfaceEntry(&mut self.row) };

        self.row.SitePrefixLength = prev_prefix_len;

        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_unicast_table() {
        let table = UnicastIpAddressTable::all().expect("Failed to get IP address table");
        println!("Found {} IP addresses", table.len());

        for address in table.iter().take(5) {
            println!(
                "Interface: {}, Family: {:?}",
                address.interface_index(),
                address.family()
            );
        }
    }
}
