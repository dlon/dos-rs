//! Example demonstrating how to retrieve network adapter information
//!
//! This example shows how to use the `get_adapters_addresses` function to
//! get information about all network adapters/addresses on the system.

use std::io;

#[cfg(feature = "net")]
pub fn main() -> io::Result<()> {
    use dos::net::{AdapterAddressFlags, get_adapters_addresses};

    println!("Network Adapters Information");
    println!("============================\n");

    // Get all adapters with comprehensive information
    let flags = AdapterAddressFlags::INCLUDE_PREFIX
        | AdapterAddressFlags::INCLUDE_GATEWAYS
        | AdapterAddressFlags::INCLUDE_ALL_INTERFACES;

    let adapters = get_adapters_addresses(None, flags)?;

    for (i, adapter) in adapters.into_iter().enumerate() {
        println!("Adapter #{i}");
        println!("  Name: {}", adapter.adapter_name());
        println!(
            "  Friendly Name: {}",
            adapter.friendly_name().to_string_lossy()
        );
        println!("  Description: {}", adapter.description().to_string_lossy());
        println!("  MTU: {} bytes", adapter.mtu());

        println!(
            "  Interface LUID: {:#018x}",
            u64::from(adapter.interface_luid())
        );
        println!();
    }

    Ok(())
}

#[cfg(not(feature = "net"))]
pub fn main() -> io::Result<()> {
    println!("This example requires the 'net' feature to be enabled.");
    println!("Run with: cargo run --features net --example get_adapters_addresses");
    Ok(())
}
