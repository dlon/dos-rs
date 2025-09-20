//! Rust-friendly bindings for Windows APIs
//!
//! This crate provides type-safe wrappers around Windows APIs, where the standard library is
//! lacking.
//!
//! # Features
//!
//! - `full` - Enable all features
//! - `net` - Network interface and IP address information
//! - `process` - Process and module enumeration using Tool Help Library
//! - `security` - Security information retrieval for Windows objects
//! - `string` - String conversion utilities with comprehensive code page support
//!
//! # Examples
//!
//! ## Process enumeration
//!
//! List all running processes in the system:
//!
//! ```no_run
//! # #[cfg(feature = "process")]
//! # {
//! use dos::process::ProcessSnapshot;
//!
//! let snapshot = ProcessSnapshot::processes()?;
//! for process in snapshot.iter_processes().take(5) {
//!     let process = process?;
//!     println!("Process ID: {}, Parent ID: {}", process.pid(), process.parent_pid());
//! }
//! # }
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! See [process].
//!
//! ## Networking
//!
//! Get all unicast IP addresses on the system:
//!
//! ```no_run
//! # #[cfg(feature = "net")]
//! # {
//! use dos::net::UnicastIpAddressTable;
//!
//! for address in UnicastIpAddressTable::all()? {
//!     println!("Interface Index: {}", address.interface_index());
//!     println!("Address Family: {:?}", address.family());
//! }
//! # }
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! See [net].
//!
//! ## Strings
//!
//! Convert from various code pages to Rust strings:
//!
//! ```no_run
//! # #[cfg(feature = "string")]
//! # {
//! use dos::string::{from_multibyte, CodePage};
//!
//! // Convert UTF-8 encoded C string to an OsString
//! let c_str = c"Hello, World!";
//! let os_string = from_multibyte(c_str, CodePage::Utf8)?;
//! println!("Converted: {:?}", os_string);
//!
//! // Convert from Windows-1252 (Western European)
//! let c_str = c"Caf\xe9"; // "Café" in Windows-1252
//! let os_string = from_multibyte(c_str, CodePage::Windows1252)?;
//! println!("From Windows-1252: {:?}", os_string);
//! # }
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! See [string].

#![cfg(target_os = "windows")]

#[cfg(feature = "net")]
pub mod net;
#[cfg(feature = "process")]
pub mod process;
#[cfg(feature = "security")]
pub mod security;
#[cfg(feature = "string")]
pub mod string;

#[cfg(any(feature = "process", feature = "string"))]
mod util;
