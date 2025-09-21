//! Example demonstrating how to monitor network interface changes
//!
//! This example shows how to use the `notify_ip_interface_change` function to
//! register a callback that gets invoked when network interfaces are added,
//! removed, or their parameters change.
//!
//! Run with: `cargo run --example monitor_interface_changes`

use std::io;

#[cfg(feature = "net")]
fn main() -> io::Result<()> {
    use dos::net::{NotificationType, get_ip_interface_entry, notify_ip_interface_change};
    use std::thread;
    use std::time::Duration;

    println!("Starting network interface change monitor...");

    // Register for interface change notifications for all families
    let _handle = notify_ip_interface_change(
        None, // Monitor all address families
        |notification_type| {
            match notification_type {
                NotificationType::InitialNotification => {
                    println!("[INIT] Interface change monitoring registered successfully");
                }
                NotificationType::AddInstance(interface) => {
                    // Fill in more details
                    let updated = get_ip_interface_entry(
                        interface.as_raw().InterfaceLuid,
                        interface.family(),
                    );
                    let interface = updated.as_ref().unwrap_or(interface);
                    println!(
                        "[ADD] Interface added - LUID: {:#x}, Family: {:?}, Metric: {}, MTU: {}",
                        interface.interface_luid(),
                        interface.family(),
                        interface.metric(),
                        interface.mtu()
                    );
                }
                NotificationType::DeleteInstance(interface) => {
                    // Fill in more details
                    let updated = get_ip_interface_entry(
                        interface.as_raw().InterfaceLuid,
                        interface.family(),
                    );
                    let interface = updated.as_ref().unwrap_or(interface);
                    println!(
                        "[DELETE] Interface removed - LUID: {:#x}, Family: {:?}",
                        interface.interface_luid(),
                        interface.family()
                    );
                }
                NotificationType::ParameterNotification(interface) => {
                    // Fill in more details
                    let updated = get_ip_interface_entry(
                        interface.as_raw().InterfaceLuid,
                        interface.family(),
                    );
                    let interface = updated.as_ref().unwrap_or(interface);
                    println!(
                        "[CHANGE] Interface parameter changed - LUID: {:#x}, Family: {:?}, Metric: {}, MTU: {}, Auto Metric: {}",
                        interface.interface_luid(),
                        interface.family(),
                        interface.metric(),
                        interface.mtu(),
                        interface.automatic_metric()
                    );
                }
            }
        },
        true, // Request initial notification
    )?;

    println!("Monitor registered. Try the following to see notifications:");
    println!("1. Disable/enable a network adapter");
    println!("2. Change network adapter properties (metric, MTU, etc.)");
    println!("3. Connect/disconnect network cables");
    println!("4. Connect/disconnect to Wi-Fi networks");
    println!();

    loop {
        thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(not(feature = "net"))]
fn main() -> io::Result<()> {
    Ok(())
}
