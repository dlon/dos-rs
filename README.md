# dos

⚠️ **This project is a work in progress.**

Rust-friendly bindings for Windows APIs. It is not meant to be exhaustive, only cover areas that
the standard library does not.

## Quick start

Add this to your `Cargo.toml`:

```toml
[dependencies]
dos = "0.0.1"
```

## Features

- `full` - Enable all features
- `net` - Networking
- `process` - Process and module enumeration
- `string` - String conversion utilities
- `security` - Security and access control
- `sys` - System information

## Guiding principles

In descending order of importance:

- **Safety**. `unsafe` must be avoided as much as possible, particularly in public APIs.
- **Lightweight**. Everything is feature-gated, especially dependencies.
- **Zero cost**. Except when it can be justified, we try to avoid needlessly copying data or performing
  unnecessary operations.
- **Escape hatch**. If higher level bindings miss anything, it should be possible to use the raw
  bindings.
- **Minimalism**. APIs should if possible resemble one-to-one mappings to the underlying Windows
  APIs, but with different naming conventions. This improves searchability. For example, the
  underlying `GetUnicastIpAddressTable` API is called `get_unicast_ip_address_table`.

## Examples

### List processes

List all running processes in the system:

```rust
use dos::process::{SnapshotFlags, create_toolhelp32_snapshot};

let snapshot = create_toolhelp32_snapshot(SnapshotFlags::PROCESS, 0)?;
for process in snapshot.processes().take(5) {
    let process = process?;
    println!("Process ID: {}, Parent ID: {}", process.pid(), process.parent_pid());
}
```

### Networking

Get all unicast IP addresses on the system:

```rust
use dos::net::get_unicast_ip_address_table;

for address in get_unicast_ip_address_table(None)? {
    println!("Interface Index: {}", address.interface_index());
    println!("Address: {}", address.address());
    println!("Address Family: {:?}", address.family());
}
```

### Security

Get a security descriptor for a file:

```rust
use dos::security::{get_security_info, SecurityInformation, ObjectType};
use std::fs::File;

let file = File::open("example.txt")?;
let security_info = get_security_info(
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

### Strings

Convert from various code pages to Rust strings:

```rust
use dos::string::{multi_byte_to_wide_char, CodePage};

// Convert UTF-8 encoded C string to an OsString
let c_str = c"Hello, World!";
let os_string = multi_byte_to_wide_char(c_str, CodePage::Utf8)?;
println!("Converted: {:?}", os_string);

// Convert from Windows-1252 (Western European)
let c_str = c"Caf\xe9"; // "Café" in Windows-1252
let os_string = multi_byte_to_wide_char(c_str, CodePage::Windows1252)?;
println!("From Windows-1252: {:?}", os_string);
```

## Platform support

This crate is tested on Windows 10 or later. It may work on earlier Windows versions, but there
is no guarantee of that.

## Contributing

Contributions are welcome! Please open an issue or a pull request.

License: GPL-3.0-only
