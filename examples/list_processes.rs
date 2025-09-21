//! Example showing how to list running processes and their modules using process snapshots.

use std::io;

#[cfg(feature = "process")]
pub fn main() -> Result<(), io::Error> {
    use dos::process::{SnapshotFlags, create_toolhelp32_snapshot};

    println!("Listing all running processes:\n");

    // Create a snapshot of all processes and modules
    let snapshot = create_toolhelp32_snapshot(SnapshotFlags::PROCESS | SnapshotFlags::MODULE, 0)?;

    for process in snapshot.processes().take(10) {
        let process = process?;
        println!(
            "Process ID: {}, Parent ID: {}",
            process.pid(),
            process.parent_pid()
        );
    }
    println!("... (showing first 10 processes)");

    // Create a snapshot of modules in the current process
    println!("\n\nListing modules in current process:\n");

    for module in snapshot.modules().take(5) {
        let module = module?;
        println!(
            "Module: {:?}, Base: {:p}, Size: {} bytes",
            module.name(),
            module.base_address(),
            module.size()
        );
    }
    println!("... (showing first 5 modules)");

    Ok(())
}

#[cfg(not(feature = "process"))]
fn main() -> Result<(), io::Error> {
    Ok(())
}
