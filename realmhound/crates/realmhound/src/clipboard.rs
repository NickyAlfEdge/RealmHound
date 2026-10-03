//! Reading the system clipboard.
//!
//! The Live Feed panel copies a dungeon callout by itself and drops it again once
//! the join window elapses. Dropping it must never wipe text the user copied in
//! the meantime, so the app compares the clipboard against the callout it wrote
//! before clearing.

/// Whether a clipboard currently holding `current` may be emptied by the
/// automatic callout cleanup that put `copied` there.
///
/// Only an exact match qualifies. Unreadable, non-text and empty clipboards all
/// report `None`, which keeps them (and any image, files or rich text the user
/// may have copied) intact.
fn should_clear(current: Option<&str>, copied: &str) -> bool {
    current == Some(copied)
}

/// Whether the clipboard still holds exactly `copied`, i.e. our own callout.
pub fn still_holds(copied: &str) -> bool {
    should_clear(text().as_deref(), copied)
}

/// The clipboard's current text, or `None` when it is empty, unreadable, or
/// holds something that is not plain text.
#[cfg(windows)]
fn text() -> Option<String> {
    use windows_sys::Win32::Foundation::HGLOBAL;
    use windows_sys::Win32::System::DataExchange::{
        CloseClipboard, GetClipboardData, IsClipboardFormatAvailable, OpenClipboard,
    };
    use windows_sys::Win32::System::Memory::{GlobalLock, GlobalUnlock};

    /// `CF_UNICODETEXT` from winuser.h. windows-sys exposes the clipboard
    /// functions but not the predefined format constants.
    const CF_UNICODETEXT: u32 = 13;
    /// Upper bound on the units read, so a truncated or unterminated string in
    /// someone else's clipboard window cannot make this scan run away.
    const MAX_UNITS: usize = 1 << 20;

    unsafe {
        // Not holding text at all -- e.g. an image or a file list: leave it be.
        if IsClipboardFormatAvailable(CF_UNICODETEXT) == 0 {
            return None;
        }
        // Another process may own the clipboard right now; then we simply can't
        // tell, and the callout is kept rather than risk clobbering anything.
        if OpenClipboard(0) == 0 {
            return None;
        }
        let handle = GetClipboardData(CF_UNICODETEXT);
        if handle == 0 {
            CloseClipboard();
            return None;
        }
        let hglobal: HGLOBAL = handle as HGLOBAL;
        let ptr = GlobalLock(hglobal) as *const u16;
        let text = if ptr.is_null() {
            None
        } else {
            let mut len = 0usize;
            while len < MAX_UNITS && *ptr.add(len) != 0 {
                len += 1;
            }
            let text = if len == MAX_UNITS {
                // Unterminated: unusable, and not our own callout either.
                None
            } else {
                Some(String::from_utf16_lossy(std::slice::from_raw_parts(
                    ptr, len,
                )))
            };
            GlobalUnlock(hglobal);
            text
        };
        CloseClipboard();
        text
    }
}

#[cfg(not(windows))]
fn text() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::{should_clear, still_holds};

    #[test]
    fn clears_only_the_callout_we_copied() {
        assert!(should_clear(Some("/p shatts 50 ffa"), "/p shatts 50 ffa"));
    }

    #[test]
    fn keeps_whatever_the_user_copied_since() {
        assert!(!should_clear(Some("something else"), "/p shatts 50 ffa"));
        // Longer, shorter, empty, or nothing at all: all preserved.
        assert!(!should_clear(
            Some("/p shatts 50 ffa and more"),
            "/p shatts 50 ffa"
        ));
        assert!(!should_clear(Some(""), "/p shatts 50 ffa"));
        assert!(!should_clear(None, "/p shatts 50 ffa"));
    }

    /// Reads the machine's real clipboard. Non-destructive, so it is safe to run
    /// anywhere: whatever is on the clipboard now is never this sentinel, and an
    /// unreadable or busy clipboard simply reports "not ours".
    #[test]
    fn reading_the_clipboard_never_claims_someone_elses_text() {
        assert!(!still_holds(
            "realmhound clipboard sentinel 4f3c1d9a-2b6e-4a58-9c71-0e5d8a6b7c42"
        ));
    }
}
