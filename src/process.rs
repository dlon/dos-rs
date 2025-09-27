//! Functions related to processes.
//!
//! # Examples
//!
//! List all running processes:
//!
//! ```no_run
//! use dos::process::{create_toolhelp32_snapshot, SnapshotFlags};
//!
//! let snapshot = create_toolhelp32_snapshot(SnapshotFlags::PROCESS, 0)?;
//! for process in snapshot.processes() {
//!     let process = process?;
//!     println!("Process ID: {}, Parent ID: {}", process.pid(), process.parent_pid());
//! }
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! List all modules in the current process:
//!
//! ```no_run
//! use dos::process::{create_toolhelp32_snapshot, SnapshotFlags};
//! use std::process;
//!
//! let current_pid = process::id();
//! let snapshot = create_toolhelp32_snapshot(SnapshotFlags::MODULE, current_pid)?;
//! for module in snapshot.modules() {
//!     let module = module?;
//!     println!("Module: {:?}, Base: {:p}, Size: {} bytes",
//!              module.name(), module.base_address(), module.size());
//! }
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! References:
//! * [Tool Help Library]
//!
//! [Tool Help Library]: https://learn.microsoft.com/en-us/windows/win32/api/_toolhelp/

use bitflags::bitflags;
use std::{ffi::OsString, io, mem, os::windows::io::AsRawHandle};
use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_NO_MORE_FILES, HANDLE, INVALID_HANDLE_VALUE},
    System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, PROCESSENTRY32W,
        Process32FirstW, Process32NextW, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
        TH32CS_SNAPPROCESS,
    },
};

bitflags! {
    /// Flags for [`ProcessSnapshot::new`] specifying what to include in the snapshot.
    ///
    /// These correspond to the `TH32CS_*` constants from the Windows API.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct SnapshotFlags: u32 {
        // TODO: heaps
        //const HEAPLIST = TH32CS_SNAPHEAPLIST;
        /// Include all modules of the process.
        const MODULE = TH32CS_SNAPMODULE;
        /// Include all 32-bit modules of the process when called from a 64-bit process.
        const MODULE32 = TH32CS_SNAPMODULE32;
        /// Include all processes in the system.
        const PROCESS = TH32CS_SNAPPROCESS;
        // TODO: threads
        //const THREAD = TH32CS_SNAPTHREAD;
    }
}

/// A snapshot of process modules and heaps.
///
/// This uses the [`CreateToolhelp32Snapshot`] Windows API function.
///
/// [`CreateToolhelp32Snapshot`]: https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
pub fn create_toolhelp32_snapshot(
    flags: SnapshotFlags,
    process_id: u32,
) -> io::Result<ProcessSnapshot> {
    ProcessSnapshot::new(flags, process_id)
}

/// A snapshot of process modules and heaps.
///
/// See [create_toolhelp32_snapshot].
///
/// This uses the [`CreateToolhelp32Snapshot`] Windows API function.
///
/// [`CreateToolhelp32Snapshot`]: https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
pub struct ProcessSnapshot {
    handle: HANDLE,
}

impl ProcessSnapshot {
    /// Create a snapshot of all processes in the system.
    pub fn new_processes() -> io::Result<ProcessSnapshot> {
        Self::new(SnapshotFlags::PROCESS, 0)
    }

    /// Create a snapshot of modules in the specified process.
    ///
    /// `process_id` can be `0` to indicate the current process.
    pub fn new_modules(process_id: u32) -> io::Result<ProcessSnapshot> {
        Self::new(SnapshotFlags::MODULE, process_id)
    }

    /// Create a snapshot of 32-bit modules in the specified process when called from a 64-bit process.
    ///
    /// `process_id` can be `0` to indicate the current process.
    pub fn new_modules32(process_id: u32) -> io::Result<ProcessSnapshot> {
        Self::new(SnapshotFlags::MODULE32, process_id)
    }

    /// Create a new process snapshot using [`CreateToolhelp32Snapshot`] with custom flags.
    ///
    /// [`CreateToolhelp32Snapshot`]: https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
    fn new(flags: SnapshotFlags, process_id: u32) -> io::Result<ProcessSnapshot> {
        // SAFETY: Trivially safe
        let snap = unsafe { CreateToolhelp32Snapshot(flags.bits(), process_id) };

        if snap == INVALID_HANDLE_VALUE {
            Err(io::Error::last_os_error())
        } else {
            Ok(ProcessSnapshot { handle: snap })
        }
    }

    /// Return the raw handle
    pub fn as_raw(&self) -> HANDLE {
        self.handle
    }

    /// Return an iterator over the modules in the snapshot
    pub fn modules(&self) -> ProcessSnapshotModules<'_> {
        let entry = MODULEENTRY32W {
            dwSize: mem::size_of::<MODULEENTRY32W>() as u32,
            ..Default::default()
        };

        ProcessSnapshotModules {
            snapshot: self,
            iter_started: false,
            temp_entry: entry,
        }
    }

    /// Return an iterator over the processes in the snapshot
    pub fn processes(&self) -> ProcessSnapshotEntries<'_> {
        let entry = PROCESSENTRY32W {
            dwSize: mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        ProcessSnapshotEntries {
            snapshot: self,
            iter_started: false,
            temp_entry: entry,
        }
    }
}

impl AsRawHandle for ProcessSnapshot {
    fn as_raw_handle(&self) -> std::os::windows::prelude::RawHandle {
        self.handle
    }
}

impl Drop for ProcessSnapshot {
    fn drop(&mut self) {
        // SAFETY: This is a valid handle
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

/// Description of a snapshot module entry. See [`MODULEENTRY32W`].
///
/// [`MODULEENTRY32W`]: https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-moduleentry32w
pub struct ModuleEntry {
    entry: MODULEENTRY32W,
}

impl ModuleEntry {
    /// Get the module name
    pub fn name(&self) -> OsString {
        let name_ptr = &raw const self.entry.szModule[0];
        // SAFETY: `name_ptr` is a null-terminated string
        unsafe { crate::util::osstring_from_wide(name_ptr) }
    }

    /// Get the module base address (in the owning process)
    pub fn base_address(&self) -> *const u8 {
        self.entry.modBaseAddr
    }

    /// Get the size of the module (in bytes)
    pub fn size(&self) -> usize {
        usize::try_from(self.entry.modBaseSize).unwrap()
    }

    /// Get the raw `MODULEENTRY32W` structure
    pub fn as_raw(&self) -> &MODULEENTRY32W {
        &self.entry
    }
}

/// Module iterator for [ProcessSnapshot]
pub struct ProcessSnapshotModules<'a> {
    snapshot: &'a ProcessSnapshot,
    iter_started: bool,
    temp_entry: MODULEENTRY32W,
}

impl Iterator for ProcessSnapshotModules<'_> {
    type Item = io::Result<ModuleEntry>;

    fn next(&mut self) -> Option<io::Result<ModuleEntry>> {
        if self.iter_started {
            // SAFETY: The snapshot is valid for 'a, and entry points to a valid `MODULEENTRY32W`
            if unsafe { Module32NextW(self.snapshot.as_raw(), &mut self.temp_entry) } == 0 {
                let last_error = io::Error::last_os_error();

                return if last_error.raw_os_error().unwrap() as u32 == ERROR_NO_MORE_FILES {
                    None
                } else {
                    Some(Err(last_error))
                };
            }
        } else {
            // SAFETY: The snapshot is valid for 'a, and entry points to a valid `MODULEENTRY32W`
            if unsafe { Module32FirstW(self.snapshot.as_raw(), &mut self.temp_entry) } == 0 {
                return Some(Err(io::Error::last_os_error()));
            }
            self.iter_started = true;
        }

        // TODO: A bit unsure about lifetimes here
        Some(Ok(ModuleEntry {
            entry: self.temp_entry,
        }))
    }
}

/// Description of a snapshot process entry. See [`PROCESSENTRY32W`].
///
/// [`PROCESSENTRY32W`]: https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32w
pub struct ProcessEntry {
    entry: PROCESSENTRY32W,
}

impl ProcessEntry {
    /// Get the process identifier
    pub fn pid(&self) -> u32 {
        self.entry.th32ProcessID
    }

    /// Get the parent process identifier
    pub fn parent_pid(&self) -> u32 {
        self.entry.th32ParentProcessID
    }

    /// Get the raw `PROCESSENTRY32W` structure
    pub fn as_raw(&self) -> &PROCESSENTRY32W {
        &self.entry
    }
}

/// Process iterator for [ProcessSnapshot]
pub struct ProcessSnapshotEntries<'a> {
    snapshot: &'a ProcessSnapshot,
    iter_started: bool,
    temp_entry: PROCESSENTRY32W,
}

impl Iterator for ProcessSnapshotEntries<'_> {
    type Item = io::Result<ProcessEntry>;

    fn next(&mut self) -> Option<io::Result<ProcessEntry>> {
        if self.iter_started {
            // SAFETY: The snapshot is valid for 'a, and entry points to a valid `PROCESSENTRY32W`
            if unsafe { Process32NextW(self.snapshot.as_raw(), &mut self.temp_entry) } == 0 {
                let last_error = io::Error::last_os_error();

                return if last_error.raw_os_error().unwrap() as u32 == ERROR_NO_MORE_FILES {
                    None
                } else {
                    Some(Err(last_error))
                };
            }
        } else {
            // SAFETY: The snapshot is valid for 'a, and entry points to a valid `PROCESSENTRY32W`
            if unsafe { Process32FirstW(self.snapshot.as_raw(), &mut self.temp_entry) } == 0 {
                return Some(Err(io::Error::last_os_error()));
            }
            self.iter_started = true;
        }

        // We copy the entry here, which is fine since it's POD
        Some(Ok(ProcessEntry {
            entry: self.temp_entry,
        }))
    }
}
