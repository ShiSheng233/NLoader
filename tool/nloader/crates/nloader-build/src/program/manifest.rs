//! MANIFEST entry generation (PLAN §6.2). The generated line must parse
//! under core's `nlr_manifest_parse` grammar: five `|`-separated fields, an
//! optional sixth support column, printable-ASCII tokens, display names at
//! most 24 characters, and the file column confined to `APPS/`.
//!
//! The kind string comes from [`super::ProgramKind::label`] while the file
//! header's numeric kind comes from [`super::ProgramKind::code`]; both derive
//! from one value, so the two declarations cannot disagree — the mismatch a
//! load must refuse is unrepresentable here.

use crate::{Error, Result};

use super::ProgramKind;

/// The comment header PLAN §6.2 shows above the entry lines.
pub const MANIFEST_HEADER: &str = "# id | kind | 显示名 | 文件 | min_abi | 支持机型/固件（可省）";

/// One MANIFEST declaration, independent of the file bytes: a program's
/// identity, its kind (shared with the packaged header), its card file, the
/// minimum API version it needs, and an optional model/firmware list.
#[derive(Debug, Clone)]
pub struct ManifestEntry {
    pub id: String,
    pub kind: ProgramKind,
    pub display_name: String,
    /// The MANIFEST file column, relative to the loader root and inside APPS.
    pub file: String,
    pub min_abi: u32,
    /// Optional comma-separated `model/firmware` tokens.
    pub models: Option<String>,
    /// A foreground program that runs over the live picture (role
    /// `shell`): its MANIFEST kind is `shell`, which core reads as
    /// foreground with the shell mark, so the line and the file's own
    /// description name the same role.
    pub shell: bool,
}

fn invalid(message: impl Into<String>) -> Error {
    Error::Object(message.into())
}

/// Printable ASCII without spaces (core's `is_token_byte`).
fn is_token_byte(byte: u8) -> bool {
    byte > 0x20 && byte < 0x7f && byte != b'|'
}

/// Printable ASCII including spaces (core's `is_name_byte`).
fn is_name_byte(byte: u8) -> bool {
    (0x20..0x7f).contains(&byte) && byte != b'|'
}

/// Validate one declaration and render its MANIFEST line. The checks mirror
/// core's parser so a generated line can never be rejected there for
/// content reasons.
pub fn manifest_line(entry: &ManifestEntry) -> Result<String> {
    let id = entry.id.as_bytes();
    if id.is_empty() || id.len() > 32 || id[0] == b'#' {
        return Err(invalid(
            "id must be 1..=32 printable-ASCII bytes without spaces",
        ));
    }
    if !id.iter().all(|byte| is_token_byte(*byte)) {
        return Err(invalid(
            "id must be 1..=32 printable-ASCII bytes without spaces",
        ));
    }
    let name = entry.display_name.as_bytes();
    if name.is_empty()
        || name.len() > 24
        || entry.display_name.trim_matches(' ') != entry.display_name
        || !name.iter().all(|byte| is_name_byte(*byte))
    {
        return Err(invalid(
            "display_name must be 1..=24 printable ASCII characters",
        ));
    }
    let file = entry.file.as_bytes();
    if file.len() <= 5
        || file.len() > 64
        || !file
            .iter()
            .all(|byte| is_token_byte(*byte) && *byte != b':')
        || !entry.file.starts_with("APPS/")
        || entry.file.contains("..")
    {
        return Err(invalid(
            "file must be an APPS/ path of at most 64 printable-ASCII bytes without ':' or '..'",
        ));
    }
    if entry.min_abi == super::package::INCOMPATIBLE_ABI_VERSION {
        return Err(invalid(
            "ABI 3 has incompatible experimental layouts; rebuild for ABI 4",
        ));
    }
    if entry.min_abi == 0 || entry.min_abi > super::package::MAX_ABI_VERSION {
        return Err(invalid(format!(
            "min_abi must be between 1 and {} (the runtime API-table version)",
            super::package::MAX_ABI_VERSION
        )));
    }
    let models = match &entry.models {
        None => String::new(),
        Some(models) => {
            let bytes = models.as_bytes();
            if bytes.is_empty() || bytes.len() > 128 {
                return Err(invalid("models must be at most 128 bytes when present"));
            }
            for token in models.split(',') {
                let token = token.trim_matches([' ', '\t']);
                let slash = token
                    .char_indices()
                    .filter(|(_, character)| *character == '/')
                    .count();
                if token.is_empty()
                    || slash != 1
                    || !token
                        .split('/')
                        .all(|half| !half.is_empty() && half.bytes().all(is_token_byte))
                {
                    return Err(invalid(
                        "models must be comma-separated model/firmware tokens",
                    ));
                }
            }
            format!(" | {models}")
        }
    };
    let kind = match (entry.shell, entry.kind) {
        (false, kind) => kind.label(),
        (true, ProgramKind::Foreground) => "shell",
        (true, ProgramKind::ResourceExtension) => {
            return Err(invalid("only a foreground program can be a shell"))
        }
    };
    Ok(format!(
        "{} | {} | {} | {} | {}{}",
        entry.id, kind, entry.display_name, entry.file, entry.min_abi, models
    ))
}

/// The full MANIFEST file content for one program: the PLAN comment header
/// followed by the entry line and a newline.
pub fn manifest_file(entry: &ManifestEntry) -> Result<String> {
    Ok(format!("{}\n{}\n", MANIFEST_HEADER, manifest_line(entry)?))
}
