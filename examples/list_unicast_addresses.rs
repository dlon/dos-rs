//! Example showing how to list unicast IP addresses on the system.

use std::io;

#[cfg(feature = "net")]
fn main() -> Result<(), io::Error> {
    use dos::net::UnicastIpAddressTable;

    println!("Listing all unicast IP addresses on the system:\n");

    let table = UnicastIpAddressTable::all()?;
    for (i, address) in table.iter().enumerate() {
        println!("Address {}:", i + 1);
        println!("  Interface Index: {}", address.interface_index());
        println!("  Address Family: {:?}", address.family());
        println!("  Interface LUID: {:#x}", address.interface_luid());
        println!(
            "  IP Address: {}/{}",
            address.address(),
            address.prefix_length()
        );
        println!();
    }

    Ok(())
}

#[cfg(not(feature = "net"))]
fn main() -> Result<(), io::Error> {
    Ok(())
}
