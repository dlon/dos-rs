use std::{
    ffi::{OsStr, OsString},
    os::windows::ffi::{OsStrExt, OsStringExt},
};

#[macro_export]
macro_rules! define_int_enum {
    ($enum_doc:expr, $repr_type:ty, $enum_name:ident { $($variant:ident = $value:expr, $doc:expr;)* }) => {
        #[doc = $enum_doc]
        #[repr($repr_type)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $enum_name {
            $(
                #[doc = $doc]
                $variant = $value,
            )*
        }

        impl From<$enum_name> for $repr_type {
            fn from(cp: $enum_name) -> $repr_type {
                cp as $repr_type
            }
        }

        impl TryFrom<$repr_type> for $enum_name {
            type Error = ();

            fn try_from(value: $repr_type) -> Result<Self, Self::Error> {
                match value {
                    $(x if x == $value => Ok($enum_name::$variant),)*
                    _ => Err(()),
                }
            }
        }
    };
}

/// Retrieve the length of `s`, a null-terminated UTF-16 string.
///
/// # Safety
///
/// `s` must be null-terminated.
pub unsafe fn wcslen(s: *const u16) -> usize {
    let mut current = s;
    while unsafe { std::ptr::read_unaligned(current) } != 0 {
        current = unsafe { current.add(1) };
    }
    usize::try_from(unsafe { current.offset_from(s) }).unwrap()
}

/// Convert `s` into an `OsString`.
///
/// # Safety
///
/// `s` must be null-terminated, initialized, and aligned.
pub unsafe fn osstring_from_wide(s: *const u16) -> OsString {
    // SAFETY: `s` is null-terminated;
    let len = unsafe { wcslen(s) };
    // SAFETY: See function docs
    unsafe { osstring_from_wide_with_len(s, len) }
}

/// Convert `s` into an `OsString`.
///
/// # Safety
///
/// `s` must be at least `len` chars long, initialized, and aligned.
pub unsafe fn osstring_from_wide_with_len(s: *const u16, len: usize) -> OsString {
    // SAFETY: `s` is initialized
    let slice = unsafe { std::slice::from_raw_parts(s, len) };
    OsString::from_wide(slice)
}

/// Convert `s` into a null-terminated wide string.
pub fn string_to_null_terminated_utf16<T: FromIterator<u16>>(s: impl AsRef<OsStr>) -> T {
    s.as_ref()
        .encode_wide()
        .chain(std::iter::once(0u16))
        .collect()
}
