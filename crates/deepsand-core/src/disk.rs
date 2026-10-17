//! How much disk a project folder occupies.
//!
//! The walk is deliberate about four things:
//!
//! * It counts regular files only, and does not follow a symlink. Following one would let a
//!   project report the size of a directory it does not contain, and a link loop would never
//!   finish.
//! * A hard link is the same bytes under a second name, not a second copy. Each physical file
//!   is counted once; a build tree full of hard links otherwise reports far more than the disk
//!   is actually holding.
//! * A file that cannot be read is not an error. The answer is marked incomplete instead, so
//!   the window can show a lower bound rather than hiding the number it *could* measure.
//! * It uses an explicit stack rather than recursion. A deeply nested `node_modules` is not a
//!   reason to exhaust the stack.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// The size of a folder, and whether every entry could be measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DiskUsage {
    /// Total size of the physical files that could be measured, each counted once.
    pub bytes: u64,
    /// False when some entry could not be read, so `bytes` is a lower bound.
    pub complete: bool,
}

/// Sum the regular files under `root` without following symlinks.
///
/// A missing or unreadable root produces `bytes = 0, complete = false`: there was nothing to
/// measure, which is different from a folder that is genuinely empty.
pub fn directory_size(root: &Path) -> DiskUsage {
    let mut total = 0u64;
    let mut complete = true;
    // Only files with more than one name go in here, so this stays small even in a huge tree.
    let mut seen_links: HashSet<(u64, u64)> = HashSet::new();
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => {
                complete = false;
                continue;
            }
        };

        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => {
                    complete = false;
                    continue;
                }
            };
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(_) => {
                    complete = false;
                    continue;
                }
            };
            if file_type.is_symlink() {
                // Not followed: see the module comment.
                continue;
            }
            if file_type.is_dir() {
                stack.push(entry.path());
                continue;
            }
            if file_type.is_file() {
                match entry.metadata() {
                    Ok(metadata) => {
                        // A hard link is another name for bytes already counted, not a second
                        // copy. Without this, a Cargo `target/` reports several GB more than
                        // the disk is holding.
                        if let Some(key) = hard_link_key(&entry.path(), &metadata) {
                            if !seen_links.insert(key) {
                                continue;
                            }
                        }
                        total = total.saturating_add(metadata.len());
                    }
                    Err(_) => complete = false,
                }
            }
            // Sockets, devices and FIFOs are not files a project folder holds, and they have no
            // size that means anything for "disk used".
        }
    }

    DiskUsage {
        bytes: total,
        complete,
    }
}

/// The identity of a file that may have more than one name.
///
/// `None` for the ordinary case of one link, so the set of seen identities stays small even
/// in a tree with hundreds of thousands of files.
fn hard_link_key(path: &Path, metadata: &std::fs::Metadata) -> Option<(u64, u64)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() > 1 {
            return Some((metadata.dev(), metadata.ino()));
        }
        None
    }
    #[cfg(windows)]
    {
        // `std` keeps the number of links and the file index behind an unstable feature, so
        // the one call that needs them is made directly. `metadata` is not needed here, but
        // it is the same `stat` the caller already paid for on the other platforms.
        let _ = metadata;
        windows_hard_link_key(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, metadata);
        None
    }
}

/// The Windows half of [`hard_link_key`]: open the file for attributes, ask for its identity
/// and close the handle at once.
///
/// `None` means either "one link" or "the file could not be opened". Both lead the caller to
/// count the bytes; the second can only make the answer a little high, never low.
#[cfg(windows)]
fn windows_hard_link_key(path: &Path) -> Option<(u64, u64)> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING,
    };

    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: `wide` is NUL-terminated and lives until `CreateFileW` returns. `handle` is
    // checked against INVALID_HANDLE_VALUE before use, and is closed exactly once, before
    // returning, so no raw handle escapes.
    unsafe {
        let handle = CreateFileW(
            wide.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            0,
        );
        if handle == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut info: BY_HANDLE_FILE_INFORMATION = std::mem::zeroed();
        let ok = GetFileInformationByHandle(handle, &mut info);
        CloseHandle(handle);
        if ok == 0 || info.nNumberOfLinks <= 1 {
            return None;
        }
        let index = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
        Some((u64::from(info.dwVolumeSerialNumber), index))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// A scratch directory unique to this test process.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "deepsand-disk-{name}-{}-{}",
            std::process::id(),
            crate::now_ms()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the scratch directory should be creatable");
        dir
    }

    fn write(path: &Path, bytes: usize) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("the parent directory should be creatable");
        }
        let mut file = std::fs::File::create(path).expect("the test file should be creatable");
        file.write_all(&vec![b'x'; bytes])
            .expect("the test file should be writable");
    }

    /// The number is the sum of the files, at any depth, and nothing else.
    #[test]
    fn a_folder_is_the_sum_of_its_files() {
        let root = scratch("sum");
        write(&root.join("a.txt"), 3);
        write(&root.join("sub").join("b.txt"), 5);
        write(&root.join("sub").join("deeper").join("c.txt"), 7);

        let usage = directory_size(&root);
        assert_eq!(usage.bytes, 15);
        assert!(usage.complete, "every file was readable");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// An empty folder is a real answer, not an unreadable one.
    #[test]
    fn an_empty_folder_is_zero_and_complete() {
        let root = scratch("empty");
        let usage = directory_size(&root);
        assert_eq!(usage.bytes, 0);
        assert!(usage.complete);

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A missing folder has nothing to measure, and saying so is different from saying "0".
    #[test]
    fn a_missing_folder_is_incomplete() {
        let usage = directory_size(&std::env::temp_dir().join(
            "deepsand-disk-this-directory-does-not-exist-4d8a2f1c",
        ));
        assert_eq!(usage.bytes, 0);
        assert!(!usage.complete);
    }

    /// A link is counted as a link, not as whatever it points at: the size of a project must
    /// not depend on something outside it. On Windows an ordinary user may not be allowed to
    /// create the link, so that half is skipped when the operating system refuses.
    #[test]
    fn a_symlink_does_not_pull_in_its_target() {
        let root = scratch("link");
        let outside = scratch("link-target");
        write(&outside.join("huge.bin"), 4096);
        write(&root.join("inside.txt"), 2);

        if make_link(&outside.join("huge.bin"), &root.join("huge-link")).is_ok() {
            let usage = directory_size(&root);
            assert_eq!(
                usage.bytes, 2,
                "only the file inside the project may be counted"
            );
            assert!(usage.complete, "a skipped link is not an unreadable entry");
        }

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// Two names for one file are one file. Cargo's build tree is full of hard links, and
    /// counting every name is what made a 48 GB project report 57 GB.
    #[test]
    fn a_hard_link_is_counted_once() {
        let root = scratch("hard-link");
        write(&root.join("original.bin"), 11);

        // Hard links are ordinary on every filesystem this app runs from, so a failure here is
        // a broken test rather than a reason to skip it.
        std::fs::hard_link(
            &root.join("original.bin"),
            &root.join("second-name.bin"),
        )
        .expect("the scratch filesystem should support hard links");

        let usage = directory_size(&root);
        assert_eq!(
            usage.bytes, 11,
            "the two names refer to the same bytes, not two copies"
        );
        assert!(usage.complete);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    fn make_link(target: &Path, link: &Path) -> std::io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }

    #[cfg(windows)]
    fn make_link(target: &Path, link: &Path) -> std::io::Result<()> {
        std::os::windows::fs::symlink_file(target, link)
    }
}
