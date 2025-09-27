//! Example demonstrating how to monitor route changes
//!
//! This example shows how to use the `notify_route_change` function to
//! register a callback that gets invoked when network routes are added,
//! removed, or their parameters change.
//!
//! Run with: `cargo run --example monitor_route_changes`

use std::io;

#[cfg(feature = "net")]
fn main() -> io::Result<()> {
    use dos::net::{NotificationType, get_ip_forward_entry, notify_route_change};
    use std::thread;
    use std::time::Duration;

    println!("Starting network route change monitor...");

    // Register for route change notifications for all families
    let _handle = notify_route_change(
        None, // Monitor all address families
        |notification_type| {
            match notification_type {
                NotificationType::InitialNotification => {
                    println!("[INIT] Route change monitoring registered successfully");
                }
                NotificationType::AddInstance(row) => {
                    // Fill in more details
                    let dest = row.destination_prefix();
                    let updated = get_ip_forward_entry(row.interface_luid(), dest.0, dest.1);
                    let row = updated.as_ref().unwrap_or(row);
                    println!(
                        "[ADD] Route added - LUID: {:#x}, Destination: {:?}, Metric: {}",
                        *row.interface_luid(),
                        row.destination_prefix(),
                        row.metric(),
                    );
                }
                NotificationType::DeleteInstance(row) => {
                    // Fill in more details
                    let dest = row.destination_prefix();
                    let updated = get_ip_forward_entry(row.interface_luid(), dest.0, dest.1);
                    let row = updated.as_ref().unwrap_or(row);
                    println!(
                        "[DELETE] Route removed - LUID: {:#x}, Destination: {:?}",
                        *row.interface_luid(),
                        row.destination_prefix(),
                    );
                }
                NotificationType::ParameterNotification(row) => {
                    // Fill in more details
                    let dest = row.destination_prefix();
                    let updated = get_ip_forward_entry(row.interface_luid(), dest.0, dest.1);
                    let row = updated.as_ref().unwrap_or(row);
                    println!(
                        "[DELETE] Route changed - LUID: {:#x}, Destination: {:?}",
                        *row.interface_luid(),
                        row.destination_prefix(),
                    );
                }
            }
        },
        true, // Request initial notification
    )?;

    println!("Monitor registered");
    println!();

    loop {
        thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(not(feature = "net"))]
fn main() -> io::Result<()> {
    Ok(())
}
