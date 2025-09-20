# dos-rs

⚠️ **This project is a work in progress.**

Rust-friendly bindings for Windows APIs, providing type-safe wrappers. It is not meant to be
exhaustive, only cover areas that the standard library does not.

## Quick start

Add this to your `Cargo.toml`:

```toml
[dependencies]
dos = "0.0.1"
```

### Available features

- `net` - Networking
- `process` - Process and module enumeration
- `string` - String conversion utilities
- `security` - Security and access control
- `full` - Enable all features (default)

## Examples

### List processes

List all running processes in the system:

```rust
use dos::process::ProcessSnapshot;

let snapshot = ProcessSnapshot::processes()?;
for process in snapshot.iter_processes().take(5) {
    let process = process?;
    println!("Process ID: {}, Parent ID: {}", process.pid, process.parent_pid);
}
```

### Networking

Get all unicast IP addresses on the system:

```rust
use dos::net::UnicastIpAddressTable;

for address in UnicastIpAddressTable::all()? {
    println!("Interface Index: {}", address.interface_index());
    println!("Address: {}", address.address());
    println!("Address Family: {:?}", address.family());
}
```

### Security information

Get a security descriptor for a file:

```rust
use dos::security::{SecurityInfo, SecurityInformation, ObjectType};
use std::fs::File;

let file = File::open("example.txt")?;
let security_info = SecurityInfo::get(
    &file,
    ObjectType::File,
    SecurityInformation::OWNER | SecurityInformation::GROUP
)?;

if let Some(owner) = security_info.owner() {
    println!("File has owner SID");
}

if let Some(group) = security_info.group() {
    println!("File has group SID");
}
```

## Platform support

This crate currently requires Windows 10 or later.

## License

This project is licensed under the GPL-3.0 license. See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
