//! Example showing how to convert strings from various code pages to Rust strings.

use std::io;

#[cfg(feature = "string")]
fn main() -> Result<(), io::Error> {
    use dos::string::{CodePage, multi_byte_to_wide_char};

    // Convert UTF-8 encoded C string to an OsString
    println!("1. UTF-8 conversion:");
    let c_str = c"Hello, World!";
    let os_string = multi_byte_to_wide_char(c_str, CodePage::Utf8)?;
    println!("   Input: {:?}", c_str);
    println!("   Output: {:?}\n", os_string);

    // Convert from Windows-1252 (Western European)
    println!("2. Windows-1252 conversion:");
    let latin1_bytes = c"Caf\xe9"; // "Café" in Windows-1252
    let os_string = multi_byte_to_wide_char(latin1_bytes, CodePage::Windows1252)?;
    println!("   Input: {:?}", latin1_bytes);
    println!("   Output: {:?}\n", os_string);

    // Convert from ASCII
    println!("3. US-ASCII conversion:");
    let ascii_str = c"ASCII text only";
    let os_string = multi_byte_to_wide_char(ascii_str, CodePage::UsAscii)?;
    println!("   Input: {:?}", ascii_str);
    println!("   Output: {:?}\n", os_string);

    // Convert from ISO 8859-1 (Latin-1)
    println!("4. ISO 8859-1 conversion:");
    let iso_bytes = c"R\xe9sum\xe9"; // "Résumé" in ISO 8859-1
    let os_string = multi_byte_to_wide_char(iso_bytes, CodePage::Iso88591)?;
    println!("   Input: {:?}", iso_bytes);
    println!("   Output: {:?}\n", os_string);

    // Empty string handling
    println!("5. Empty string:");
    let empty_str = c"";
    let os_string = multi_byte_to_wide_char(empty_str, CodePage::Utf8)?;
    println!("   Input: {:?}", empty_str);
    println!("   Output: {:?}", os_string);

    Ok(())
}

#[cfg(not(feature = "string"))]
fn main() -> Result<(), io::Error> {
    Ok(())
}
