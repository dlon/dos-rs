//! Internationalization and string functionality

use std::ffi::{CStr, OsString};
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::ptr;
use windows_sys::Win32::Globalization::{
    CP_ACP, CP_MACCP, CP_OEMCP, CP_SYMBOL, CP_THREAD_ACP, CP_UTF7, CP_UTF8, MultiByteToWideChar,
};

use crate::define_int_enum;

define_int_enum!("Windows code page identifiers", u32, CodePage {
    Acp = CP_ACP, "System default ANSI code page\n\nThis may vary between systems";
    Mac = CP_MACCP, "System Macintosh code page\n\nThis may vary between systems";
    Oem = CP_OEMCP, "System OEM code page\n\nThis may vary between systems";
    Symbol = CP_SYMBOL, "Symbol code page (42)";
    ThreadAcp = CP_THREAD_ACP, "ANSI code page for the current thread\n\nThis may vary between systems";
    Ibm037 = 37, "IBM EBCDIC US-Canada";
    Ibm437 = 437, "OEM United States";
    Ibm500 = 500, "IBM EBCDIC International";
    Asmo708 = 708, "Arabic (ASMO 708)";
    Arabic709 = 709, "Arabic (ASMO-449+, BCON V4)";
    Arabic710 = 710, "Arabic - Transparent Arabic";
    Dos720 = 720, "Arabic (Transparent ASMO); Arabic (DOS)";
    Ibm737 = 737, "OEM Greek (formerly 437G); Greek (DOS)";
    Ibm775 = 775, "OEM Baltic; Baltic (DOS)";
    Ibm850 = 850, "OEM Multilingual Latin 1; Western European (DOS)";
    Ibm852 = 852, "OEM Latin 2; Central European (DOS)";
    Ibm855 = 855, "OEM Cyrillic (primarily Russian)";
    Ibm857 = 857, "OEM Turkish; Turkish (DOS)";
    Ibm858 = 858, "OEM Multilingual Latin 1 + Euro symbol";
    Ibm860 = 860, "OEM Portuguese; Portuguese (DOS)";
    Ibm861 = 861, "OEM Icelandic; Icelandic (DOS)";
    Dos862 = 862, "OEM Hebrew; Hebrew (DOS)";
    Ibm863 = 863, "OEM French Canadian; French Canadian (DOS)";
    Ibm864 = 864, "OEM Arabic; Arabic (864)";
    Ibm865 = 865, "OEM Nordic; Nordic (DOS)";
    Cp866 = 866, "OEM Russian; Cyrillic (DOS)";
    Ibm869 = 869, "OEM Modern Greek; Greek, Modern (DOS)";
    Ibm870 = 870, "IBM EBCDIC Multilingual/ROECE (Latin 2)";
    Windows874 = 874, "Thai (Windows)";
    Cp875 = 875, "IBM EBCDIC Greek Modern";
    ShiftJis = 932, "ANSI/OEM Japanese; Japanese (Shift-JIS)";
    Gb2312 = 936, "ANSI/OEM Simplified Chinese (PRC, Singapore)";
    KsC56011987 = 949, "ANSI/OEM Korean (Unified Hangul Code)";
    Big5 = 950, "ANSI/OEM Traditional Chinese (Taiwan; Hong Kong SAR, PRC)";
    Ibm1026 = 1026, "IBM EBCDIC Turkish (Latin 5)";
    Ibm1047 = 1047, "IBM EBCDIC Latin 1/Open System";
    Ibm1140 = 1140, "IBM EBCDIC US-Canada (037 + Euro symbol)";
    Ibm1141 = 1141, "IBM EBCDIC Germany (20273 + Euro symbol)";
    Ibm1142 = 1142, "IBM EBCDIC Denmark-Norway (20277 + Euro symbol)";
    Ibm1143 = 1143, "IBM EBCDIC Finland-Sweden (20278 + Euro symbol)";
    Ibm1144 = 1144, "IBM EBCDIC Italy (20280 + Euro symbol)";
    Ibm1145 = 1145, "IBM EBCDIC Latin America-Spain (20284 + Euro symbol)";
    Ibm1146 = 1146, "IBM EBCDIC United Kingdom (20285 + Euro symbol)";
    Ibm1147 = 1147, "IBM EBCDIC France (20297 + Euro symbol)";
    Ibm1148 = 1148, "IBM EBCDIC International (500 + Euro symbol)";
    Ibm1149 = 1149, "IBM EBCDIC Icelandic (20871 + Euro symbol)";
    Utf16 = 1200, "Unicode UTF-16, little endian byte order";
    Utf16Be = 1201, "Unicode UTF-16, big endian byte order";
    Windows1250 = 1250, "ANSI Central European; Central European (Windows)";
    Windows1251 = 1251, "ANSI Cyrillic; Cyrillic (Windows)";
    Windows1252 = 1252, "ANSI Latin 1; Western European (Windows)";
    Windows1253 = 1253, "ANSI Greek; Greek (Windows)";
    Windows1254 = 1254, "ANSI Turkish; Turkish (Windows)";
    Windows1255 = 1255, "ANSI Hebrew; Hebrew (Windows)";
    Windows1256 = 1256, "ANSI Arabic; Arabic (Windows)";
    Windows1257 = 1257, "ANSI Baltic; Baltic (Windows)";
    Windows1258 = 1258, "ANSI/OEM Vietnamese; Vietnamese (Windows)";
    Johab = 1361, "Korean (Johab)";
    Macintosh = 10000, "MAC Roman; Western European (Mac)";
    MacJapanese = 10001, "Japanese (Mac)";
    MacChineseTrad = 10002, "MAC Traditional Chinese (Big5)";
    MacKorean = 10003, "Korean (Mac)";
    MacArabic = 10004, "Arabic (Mac)";
    MacHebrew = 10005, "Hebrew (Mac)";
    MacGreek = 10006, "Greek (Mac)";
    MacCyrillic = 10007, "Cyrillic (Mac)";
    MacChineseSimp = 10008, "MAC Simplified Chinese (GB 2312)";
    MacRomanian = 10010, "Romanian (Mac)";
    MacUkrainian = 10017, "Ukrainian (Mac)";
    MacThai = 10021, "Thai (Mac)";
    MacCe = 10029, "MAC Latin 2; Central European (Mac)";
    MacIcelandic = 10079, "Icelandic (Mac)";
    MacTurkish = 10081, "Turkish (Mac)";
    MacCroatian = 10082, "Croatian (Mac)";
    Utf32 = 12000, "Unicode UTF-32, little endian byte order";
    Utf32Be = 12001, "Unicode UTF-32, big endian byte order";
    ChineseCns = 20000, "CNS Taiwan; Chinese Traditional (CNS)";
    Cp20001 = 20001, "TCA Taiwan";
    ChineseEten = 20002, "Eten Taiwan; Chinese Traditional (Eten)";
    Cp20003 = 20003, "IBM5550 Taiwan";
    Cp20004 = 20004, "TeleText Taiwan";
    Cp20005 = 20005, "Wang Taiwan";
    Ia5 = 20105, "IA5 (IRV International Alphabet No. 5, 7-bit)";
    Ia5German = 20106, "IA5 German (7-bit)";
    Ia5Swedish = 20107, "IA5 Swedish (7-bit)";
    Ia5Norwegian = 20108, "IA5 Norwegian (7-bit)";
    UsAscii = 20127, "US-ASCII (7-bit)";
    Cp20261 = 20261, "T.61";
    Cp20269 = 20269, "ISO 6937 Non-Spacing Accent";
    Ibm273 = 20273, "IBM EBCDIC Germany";
    Ibm277 = 20277, "IBM EBCDIC Denmark-Norway";
    Ibm278 = 20278, "IBM EBCDIC Finland-Sweden";
    Ibm280 = 20280, "IBM EBCDIC Italy";
    Ibm284 = 20284, "IBM EBCDIC Latin America-Spain";
    Ibm285 = 20285, "IBM EBCDIC United Kingdom";
    Ibm290 = 20290, "IBM EBCDIC Japanese Katakana Extended";
    Ibm297 = 20297, "IBM EBCDIC France";
    Ibm420 = 20420, "IBM EBCDIC Arabic";
    Ibm423 = 20423, "IBM EBCDIC Greek";
    Ibm424 = 20424, "IBM EBCDIC Hebrew";
    EbcdicKoreanExtended = 20833, "IBM EBCDIC Korean Extended";
    IbmThai = 20838, "IBM EBCDIC Thai";
    Koi8R = 20866, "Russian (KOI8-R); Cyrillic (KOI8-R)";
    Ibm871 = 20871, "IBM EBCDIC Icelandic";
    Ibm880 = 20880, "IBM EBCDIC Cyrillic Russian";
    Ibm905 = 20905, "IBM EBCDIC Turkish";
    Ibm924 = 20924, "IBM EBCDIC Latin 1/Open System (1047 + Euro symbol)";
    EucJp = 20932, "Japanese (JIS 0208-1990 and 0212-1990)";
    Cp20936 = 20936, "Simplified Chinese (GB2312-80)";
    Cp20949 = 20949, "Korean Wansung";
    Cp1025 = 21025, "IBM EBCDIC Cyrillic Serbian-Bulgarian";
    Koi8U = 21866, "Ukrainian (KOI8-U); Cyrillic (KOI8-U)";
    Iso88591 = 28591, "ISO 8859-1 Latin 1; Western European (ISO)";
    Iso88592 = 28592, "ISO 8859-2 Central European";
    Iso88593 = 28593, "ISO 8859-3 Latin 3";
    Iso88594 = 28594, "ISO 8859-4 Baltic";
    Iso88595 = 28595, "ISO 8859-5 Cyrillic";
    Iso88596 = 28596, "ISO 8859-6 Arabic";
    Iso88597 = 28597, "ISO 8859-7 Greek";
    Iso88598 = 28598, "ISO 8859-8 Hebrew; Hebrew (ISO-Visual)";
    Iso88599 = 28599, "ISO 8859-9 Turkish";
    Iso885913 = 28603, "ISO 8859-13 Estonian";
    Iso885915 = 28605, "ISO 8859-15 Latin 9";
    Europa = 29001, "Europa 3";
    Iso88598I = 38598, "ISO 8859-8 Hebrew; Hebrew (ISO-Logical)";
    Iso2022Jp = 50220, "ISO 2022 Japanese with no halfwidth Katakana";
    Iso2022JpAllow1ByteKana = 50221, "ISO 2022 Japanese with halfwidth Katakana";
    Iso2022JpSoSi = 50222, "ISO 2022 Japanese JIS X 0201-1989";
    Iso2022Kr = 50225, "ISO 2022 Korean";
    Cp50227 = 50227, "ISO 2022 Simplified Chinese";
    Iso2022TradChinese = 50229, "ISO 2022 Traditional Chinese";
    EbcdicJapaneseKatakana = 50930, "EBCDIC Japanese (Katakana) Extended";
    EbcdicUsCanadaJapanese = 50931, "EBCDIC US-Canada and Japanese";
    EbcdicKoreanExtendedKorean = 50933, "EBCDIC Korean Extended and Korean";
    EbcdicSimpChineseExtended = 50935, "EBCDIC Simplified Chinese Extended and Simplified Chinese";
    EbcdicSimpChinese = 50936, "EBCDIC Simplified Chinese";
    EbcdicUsCanadaTradChinese = 50937, "EBCDIC US-Canada and Traditional Chinese";
    EbcdicJapaneseLatinExtended = 50939, "EBCDIC Japanese (Latin) Extended and Japanese";
    EucJpComplete = 51932, "EUC Japanese";
    EucCn = 51936, "EUC Simplified Chinese";
    EucKr = 51949, "EUC Korean";
    EucTradChinese = 51950, "EUC Traditional Chinese";
    HzGb2312 = 52936, "HZ-GB2312 Simplified Chinese";
    Gb18030 = 54936, "GB18030 Simplified Chinese (4 byte)";
    IsciiDevanagari = 57002, "ISCII Devanagari";
    IsciiBangla = 57003, "ISCII Bangla";
    IsciiTamil = 57004, "ISCII Tamil";
    IsciiTelugu = 57005, "ISCII Telugu";
    IsciiAssamese = 57006, "ISCII Assamese";
    IsciiOdia = 57007, "ISCII Odia";
    IsciiKannada = 57008, "ISCII Kannada";
    IsciiMalayalam = 57009, "ISCII Malayalam";
    IsciiGujarati = 57010, "ISCII Gujarati";
    IsciiPunjabi = 57011, "ISCII Punjabi";
    Utf7 = CP_UTF7, "Unicode (UTF-7)";
    Utf8 = CP_UTF8, "Unicode (UTF-8)";
});

/// Convert `s`, with the given character encoding `codepage`, to an [`OsString`].
///
/// This corresponds to the [`MultiByteToWideChar`] Windows API function.
///
/// [`MultiByteToWideChar`]: https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-multibytetowidechar
pub fn multi_byte_to_wide_char(s: &CStr, codepage: CodePage) -> Result<OsString, io::Error> {
    if s.is_empty() {
        return Ok(OsString::new());
    }

    // SAFETY: `s` is null-terminated and valid.
    let wc_size = unsafe {
        MultiByteToWideChar(
            codepage.into(),
            0,
            s.as_ptr() as *const u8,
            -1,
            ptr::null_mut(),
            0,
        )
    };

    if wc_size == 0 {
        return Err(io::Error::last_os_error());
    }

    let mut wc_buffer = vec![0u16; usize::try_from(wc_size).unwrap()];

    // SAFETY: `wc_buffer` can contain up to `wc_size` characters, including a null
    // terminator.
    let chars_written = unsafe {
        MultiByteToWideChar(
            codepage.into(),
            0,
            s.as_ptr() as *const u8,
            -1,
            wc_buffer.as_mut_ptr(),
            wc_size,
        )
    };

    if chars_written == 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(OsString::from_wide(
        &wc_buffer[..usize::try_from(chars_written - 1).unwrap()],
    ))
}

#[cfg(test)]
mod test {
    use super::*;
    use std::os::windows::ffi::OsStringExt;

    #[test]
    fn test_multibyte_to_wide() {
        // € = 0x20AC in UTF-16
        let converted = multi_byte_to_wide_char(c"€€", CodePage::Utf8).unwrap();
        let expected = OsString::from_wide(&[0x20AC, 0x20AC]);
        assert_eq!(converted, expected, "unexpected result {converted:?}");

        // boundary case
        let converted = multi_byte_to_wide_char(c"", CodePage::Utf8).unwrap();
        let expected = OsString::new();
        assert_eq!(converted, expected, "unexpected result {converted:?}");
    }
}
