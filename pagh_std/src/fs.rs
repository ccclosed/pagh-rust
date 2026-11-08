//! Files, directories and metadata over the frozen syscall table.
//!
//! The kernel takes absolute paths only and has no `statat`, `O_EXCL`,
//! `O_DIRECTORY` or `O_NOFOLLOW`. The consequences are explicit:
//!
//! * every path is resolved against [`crate::env::current_dir`] and normalized
//!   lexically before the syscall;
//! * [`metadata`] is `openat(O_RDONLY)` + `fstat` + `close`, so it follows
//!   symlinks and needs the file to be openable;
//! * [`OpenOptions::create_new`] is a typed [`ErrorKind::Unsupported`] — an
//!   emulated check would be racy and would lie about `O_EXCL`;
//! * [`symlink_metadata`] is unsupported for the same reason (no
//!   `AT_SYMLINK_NOFOLLOW`), while directory entries do report the link kind
//!   from `getdents64`;
//! * [`set_permissions`] writes the kernel's per-run mode table only; nothing
//!   is persisted to the ext2 inode.
//!
//! `getdents64` yields a snapshot of the directory taken at `openat`, so
//! changes made while iterating are not observed. [`ReadDir`] filters `.` and
//! `..`, matching std.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use libpagh::abi::{dirent_size, EntryKind, Stat, DIRENT_HEADER};
use libpagh::errno::Errno;
use libpagh::sys;

use crate::error::{Error, ErrorKind, Result};
use crate::io::{self, BufRead, Read, ReadBuffer, Seek, SeekFrom, Write};
use crate::path::{Path, PathBuf};

/// Resolve `path` to the absolute, lexically-normalized form the kernel needs.
///
/// Relative paths use the process's effective `PWD` (see
/// [`crate::env::set_current_dir`]). This performs no filesystem access: a
/// missing path still normalizes, and the syscall reports `ENOENT`.
pub(crate) fn resolve_path(path: &Path) -> String {
    let base = crate::env::pwd_string();
    crate::path::normalize_join(&base, path.as_str())
}

/// The type of a filesystem entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FileType {
    /// A regular file.
    File,
    /// A directory.
    Dir,
    /// A symbolic link (as reported by `getdents64`).
    Symlink,
    /// A device, FIFO, socket or other node.
    Other,
}

impl FileType {
    /// True for a regular file.
    pub const fn is_file(self) -> bool {
        matches!(self, FileType::File)
    }

    /// True for a directory.
    pub const fn is_dir(self) -> bool {
        matches!(self, FileType::Dir)
    }

    /// True for a symbolic link.
    pub const fn is_symlink(self) -> bool {
        matches!(self, FileType::Symlink)
    }
}

impl From<EntryKind> for FileType {
    fn from(kind: EntryKind) -> FileType {
        match kind {
            EntryKind::File => FileType::File,
            EntryKind::Dir => FileType::Dir,
            EntryKind::Symlink => FileType::Symlink,
            EntryKind::Other => FileType::Other,
        }
    }
}

impl From<FileType> for EntryKind {
    fn from(kind: FileType) -> EntryKind {
        match kind {
            FileType::File => EntryKind::File,
            FileType::Dir => EntryKind::Dir,
            FileType::Symlink => EntryKind::Symlink,
            FileType::Other => EntryKind::Other,
        }
    }
}

/// Permission bits plus the current kernel's caveat.
///
/// The mode is what `fstat` reports. `set_readonly` only edits this value; use
/// [`set_permissions`] to ask the kernel (which records it for the rest of the
/// run, not on disk).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Permissions {
    mode: u32,
}

impl Permissions {
    /// Wrap a raw mode (`& 0o7777` is applied by the kernel).
    pub const fn from_mode(mode: u32) -> Permissions {
        Permissions { mode }
    }

    /// The raw `0o7777` permission bits.
    pub const fn mode(self) -> u32 {
        self.mode
    }

    /// True when no write bit is set.
    pub const fn readonly(self) -> bool {
        self.mode & 0o222 == 0
    }

    /// Set or clear all write bits in this value.
    pub fn set_readonly(&mut self, readonly: bool) {
        if readonly {
            self.mode &= !0o222;
        } else {
            self.mode |= 0o222;
        }
    }
}

/// File metadata from `fstat`.
///
/// The ABI's `Stat` has exactly four fields (mode, kind, size, inode); there is
/// no timestamp, link count, block count or device number in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Metadata {
    stat: Stat,
}

impl Metadata {
    /// File size in bytes.
    pub const fn len(&self) -> u64 {
        self.stat.size
    }

    /// File size in bytes (alias for [`Metadata::len`], matching the ABI term).
    pub const fn size(&self) -> u64 {
        self.stat.size
    }

    /// True when the file is empty.
    pub const fn is_empty(&self) -> bool {
        self.stat.size == 0
    }

    /// The entry type.
    pub const fn file_type(&self) -> FileType {
        match self.stat.entry_kind() {
            EntryKind::File => FileType::File,
            EntryKind::Dir => FileType::Dir,
            EntryKind::Symlink => FileType::Symlink,
            EntryKind::Other => FileType::Other,
        }
    }

    /// Alias for [`Metadata::file_type`].
    pub const fn kind(&self) -> FileType {
        self.file_type()
    }

    /// True for a regular file.
    pub const fn is_file(&self) -> bool {
        self.file_type().is_file()
    }

    /// True for a directory.
    pub const fn is_dir(&self) -> bool {
        self.file_type().is_dir()
    }

    /// True for a symbolic link.
    pub const fn is_symlink(&self) -> bool {
        self.file_type().is_symlink()
    }

    /// The permission bits (`0o7777`).
    pub const fn mode(&self) -> u32 {
        self.stat.mode
    }

    /// The inode number.
    pub const fn ino(&self) -> u64 {
        self.stat.ino
    }

    /// The permission bits as a [`Permissions`] value.
    pub const fn permissions(&self) -> Permissions {
        Permissions::from_mode(self.stat.mode)
    }
}

/// Options and flags for opening a file.
#[derive(Clone, Debug)]
pub struct OpenOptions {
    read: bool,
    write: bool,
    append: bool,
    truncate: bool,
    create: bool,
    create_new: bool,
    mode: u32,
}

impl OpenOptions {
    /// All flags off: the caller must enable at least read or write.
    pub const fn new() -> OpenOptions {
        OpenOptions {
            read: false,
            write: false,
            append: false,
            truncate: false,
            create: false,
            create_new: false,
            mode: 0o666,
        }
    }

    /// Open for reading.
    pub fn read(&mut self, read: bool) -> &mut OpenOptions {
        self.read = read;
        self
    }

    /// Open for writing.
    pub fn write(&mut self, write: bool) -> &mut OpenOptions {
        self.write = write;
        self
    }

    /// Write at the end of the file (implies writing).
    pub fn append(&mut self, append: bool) -> &mut OpenOptions {
        self.append = append;
        self
    }

    /// Truncate an existing file to zero length.
    pub fn truncate(&mut self, truncate: bool) -> &mut OpenOptions {
        self.truncate = truncate;
        self
    }

    /// Create the file when it is missing.
    pub fn create(&mut self, create: bool) -> &mut OpenOptions {
        self.create = create;
        self
    }

    /// Fail if the file exists.
    ///
    /// **Unsupported:** the ABI has no `O_EXCL`. The open reports an
    /// [`ErrorKind::Unsupported`] error rather than performing a racy
    /// userland "does it exist?" check.
    pub fn create_new(&mut self, create_new: bool) -> &mut OpenOptions {
        self.create_new = create_new;
        self
    }

    /// The mode passed with `O_CREAT`.
    ///
    /// The current kernel accepts and **ignores** this argument; ext2 supplies
    /// `0o644`/`0o755`. It is stored so a future kernel can honor it without a
    /// source change here.
    pub fn mode(&mut self, mode: u32) -> &mut OpenOptions {
        self.mode = mode;
        self
    }

    /// Open `path` with these options.
    pub fn open<P: AsRef<Path>>(&self, path: P) -> Result<File> {
        if self.create_new {
            return Err(Error::unsupported(
                "OpenOptions::create_new: the pagh ABI has no O_EXCL",
            ));
        }
        let writing = self.write || self.append;
        let access = match (self.read, writing) {
            (true, true) => sys::O_RDWR,
            (false, true) => sys::O_WRONLY,
            (true, false) => sys::O_RDONLY,
            (false, false) => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "OpenOptions: neither read nor write was requested",
                ))
            }
        };
        let mut flags = access;
        if self.create {
            flags |= sys::O_CREAT;
        }
        if self.truncate {
            flags |= sys::O_TRUNC;
        }
        if self.append {
            flags |= sys::O_APPEND;
        }
        let absolute = resolve_path(path.as_ref());
        let fd = sys::openat(sys::AT_FDCWD, &absolute, flags, self.mode)?;
        Ok(File {
            fd,
            read_ahead: ReadBuffer::new(),
        })
    }
}

impl Default for OpenOptions {
    fn default() -> OpenOptions {
        OpenOptions::new()
    }
}

/// An open file descriptor, closed on drop.
///
/// `File` keeps its `std`-shaped inherent API and also implements
/// [`Read`]/[`Write`]/[`Seek`] (as `std::fs::File` does) plus [`BufRead`].
/// The `BufRead` implementation is a pagh extension: `std::fs::File` does not
/// implement `BufRead`, because a plain file is unbuffered. Here `fill_buf`
/// reads ahead into an internal 8 KiB buffer; `Read` drains that buffer before
/// touching the descriptor, `Seek` accounts for the unread bytes, and `Write`
/// rewinds over them first so the logical file position stays consistent.
/// Programs that want explicit control over buffering should keep using
/// [`io::BufReader`] (the `wc` example does).
///
/// The read-ahead buffer is allocated lazily and is empty for a file that only
/// uses `read`/`write`/`seek`; `File` remains otherwise unbuffered.
/// `as_raw_fd` exposes the kernel offset, which is ahead of the logical
/// position while read-ahead is pending; `into_raw_fd` rewinds that read-ahead
/// (best effort) before handing the descriptor over. Use `BufReader` when the
/// distinction matters.
pub struct File {
    fd: i32,
    read_ahead: ReadBuffer,
}

impl core::fmt::Debug for File {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("File").field("fd", &self.fd).finish()
    }
}

impl File {
    /// Open an existing file read-only.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<File> {
        OpenOptions::new().read(true).open(path)
    }

    /// Create or truncate a file for writing.
    pub fn create<P: AsRef<Path>>(path: P) -> Result<File> {
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
    }

    /// Create a file that must not exist.
    ///
    /// Always [`ErrorKind::Unsupported`]: see [`OpenOptions::create_new`].
    pub fn create_new<P: AsRef<Path>>(path: P) -> Result<File> {
        OpenOptions::new().write(true).create_new(true).open(path)
    }

    /// A fresh [`OpenOptions`] value.
    pub fn options() -> OpenOptions {
        OpenOptions::new()
    }

    /// The raw descriptor, for the few APIs that take one directly.
    ///
    /// If `BufRead` has read ahead, the descriptor's offset is ahead of this
    /// `File`'s logical position; see the type-level note.
    pub fn as_raw_fd(&self) -> i32 {
        self.fd
    }

    /// Give up ownership of the descriptor; the caller must close it.
    ///
    /// Any pending read-ahead is rewound first (best effort), so the raw
    /// descriptor starts at the logical position this `File` reports.
    pub fn into_raw_fd(mut self) -> i32 {
        let fd = self.fd;
        let unread = self.read_ahead.unread();
        if unread > 0 {
            let _ = sys::lseek(fd, -(unread as i64), sys::SEEK_CUR);
        }
        self.read_ahead.discard();
        self.fd = -1;
        fd
    }

    /// Drop read-ahead and move the descriptor back to the logical position.
    fn discard_read_ahead(&mut self) -> Result<()> {
        let unread = self.read_ahead.unread();
        if unread > 0 {
            sys::lseek(self.fd, -(unread as i64), sys::SEEK_CUR)?;
        }
        self.read_ahead.discard();
        Ok(())
    }

    /// Take ownership of an existing descriptor.
    ///
    /// # Safety
    ///
    /// `fd` must be open and owned by this process, and must not be closed or
    /// wrapped by another `File` while this value lives.
    pub unsafe fn from_raw_fd(fd: i32) -> File {
        // SAFETY: constructing `File` performs no operation on the descriptor;
        // the caller's guarantee is what makes the eventual `Drop` and I/O
        // sound. The struct is a plain descriptor plus an empty buffer, so this
        // body contains no unsafe operation of its own.
        File {
            fd,
            read_ahead: ReadBuffer::new(),
        }
    }

    /// Metadata for the open file (`fstat`).
    pub fn metadata(&self) -> Result<Metadata> {
        let mut stat = Stat::default();
        sys::fstat(self.fd, &mut stat)?;
        Ok(Metadata { stat })
    }

    /// Resize the file (`ftruncate`).
    ///
    /// The descriptor must be writable and the file regular. The open offset
    /// is not moved, as POSIX requires. Growing fills with zeroes.
    pub fn set_len(&self, length: u64) -> Result<()> {
        sys::ftruncate(self.fd, length)?;
        Ok(())
    }

    /// Unsupported: the ABI has no `fsync`/`fdatasync`.
    pub fn sync_all(&self) -> Result<()> {
        Err(Error::unsupported(
            "File::sync_all: the pagh ABI has no fsync",
        ))
    }

    /// Unsupported: the ABI has no `fdatasync`.
    pub fn sync_data(&self) -> Result<()> {
        Err(Error::unsupported(
            "File::sync_data: the pagh ABI has no fdatasync",
        ))
    }

    /// Unsupported: the ABI has no `dup`/`fcntl`.
    pub fn try_clone(&self) -> Result<File> {
        Err(Error::unsupported(
            "File::try_clone: the pagh ABI has no dup/fcntl",
        ))
    }
}

impl Drop for File {
    fn drop(&mut self) {
        if self.fd >= 0 {
            // A close error is not recoverable from `drop`; the data path
            // already reported any earlier write failure.
            let _ = sys::close(self.fd);
        }
    }
}

impl Read for File {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let fd = self.fd;
        self.read_ahead
            .read(buf, |out| sys::read(fd, out).map_err(Error::from))
    }
}

impl Write for File {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        // If `BufRead::fill_buf` read ahead, the kernel offset is beyond this
        // File's logical position. Move it back before writing, so a
        // read-then-write sequence behaves like an unbuffered File. O_APPEND
        // ignores the offset and appends regardless, which is still correct.
        self.discard_read_ahead()?;
        sys::write(self.fd, buf).map_err(Error::from)
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

impl BufRead for File {
    fn fill_buf(&mut self) -> Result<&[u8]> {
        let fd = self.fd;
        self.read_ahead
            .fill(|out| sys::read(fd, out).map_err(Error::from))
    }

    fn consume(&mut self, amt: usize) {
        self.read_ahead.consume(amt);
    }
}

impl Seek for File {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
        let unread = self.read_ahead.unread() as i64;
        let (offset, whence) = match pos {
            SeekFrom::Start(value) => {
                let offset =
                    i64::try_from(value).map_err(|_| Error::from(libpagh::errno::Errno::EINVAL))?;
                (offset, sys::SEEK_SET)
            }
            // The descriptor is `unread` bytes ahead of the logical position.
            SeekFrom::Current(delta) => {
                let adjusted = delta
                    .checked_sub(unread)
                    .ok_or(Error::from(libpagh::errno::Errno::EINVAL))?;
                (adjusted, sys::SEEK_CUR)
            }
            SeekFrom::End(delta) => (delta, sys::SEEK_END),
        };
        let result = sys::lseek(self.fd, offset, whence)?;
        self.read_ahead.discard();
        Ok(result)
    }
}

/// Metadata for `path` (`openat` + `fstat` + `close`).
///
/// Follows symbolic links, and requires the target to be openable read-only.
/// There is no `statat`/`AT_SYMLINK_NOFOLLOW` in the ABI.
pub fn metadata<P: AsRef<Path>>(path: P) -> Result<Metadata> {
    File::open(path)?.metadata()
}

/// Unsupported: metadata for a symlink itself needs `AT_SYMLINK_NOFOLLOW`.
///
/// A directory listing still reports [`FileType::Symlink`] from `getdents64`;
/// see [`DirEntry::file_type`].
pub fn symlink_metadata<P: AsRef<Path>>(path: P) -> Result<Metadata> {
    let _ = path;
    Err(Error::unsupported(
        "symlink_metadata: the pagh ABI has no statat/AT_SYMLINK_NOFOLLOW",
    ))
}

/// Read an entire file.
pub fn read<P: AsRef<Path>>(path: P) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    io::read_to_end(&mut file)
}

/// Read an entire file and validate it as UTF-8.
pub fn read_to_string<P: AsRef<Path>>(path: P) -> Result<String> {
    let mut file = File::open(path)?;
    io::read_to_string(&mut file)
}

/// Create or truncate `path` and write all of `contents`.
pub fn write<P: AsRef<Path>, C: AsRef<[u8]>>(path: P, contents: C) -> Result<()> {
    let mut file = File::create(path)?;
    file.write_all(contents.as_ref())
}

/// Create a directory. The current kernel ignores the mode and ext2 uses
/// `0o755`.
pub fn create_dir<P: AsRef<Path>>(path: P) -> Result<()> {
    let absolute = resolve_path(path.as_ref());
    sys::mkdirat(sys::AT_FDCWD, &absolute, 0o777)?;
    Ok(())
}

/// Create `path` and every missing parent directory.
///
/// An existing component is accepted only if it is a directory; a regular file
/// in the way is `EEXIST`. `/` is a no-op.
pub fn create_dir_all<P: AsRef<Path>>(path: P) -> Result<()> {
    let absolute = resolve_path(path.as_ref());
    if absolute == "/" {
        return Ok(());
    }
    let mut prefix = String::new();
    for component in absolute.split('/').filter(|part| !part.is_empty()) {
        prefix.push('/');
        prefix.push_str(component);
        match create_dir(prefix.as_str()) {
            Ok(()) => {}
            Err(error) => {
                // `mkdir` may answer EEXIST for an existing component, and the
                // kernel also refuses to mutate a mount root such as `/mnt`
                // (ENOTSUP). Both are fine when the path already is a
                // directory; if it is not, the original error is the useful
                // one.
                match metadata(prefix.as_str()) {
                    Ok(existing) if existing.is_dir() => {}
                    _ => return Err(error),
                }
            }
        }
    }
    Ok(())
}

/// Remove a file or symbolic link.
pub fn remove_file<P: AsRef<Path>>(path: P) -> Result<()> {
    let absolute = resolve_path(path.as_ref());
    sys::unlinkat(sys::AT_FDCWD, &absolute, 0)?;
    Ok(())
}

/// Remove an **empty** directory.
pub fn remove_dir<P: AsRef<Path>>(path: P) -> Result<()> {
    let absolute = resolve_path(path.as_ref());
    sys::unlinkat(sys::AT_FDCWD, &absolute, sys::AT_REMOVEDIR)?;
    Ok(())
}

/// Remove a directory and everything below it.
///
/// Symbolic links are unlinked, never followed. A non-directory argument is
/// [`ErrorKind::NotADirectory`].
pub fn remove_dir_all<P: AsRef<Path>>(path: P) -> Result<()> {
    let path = path.as_ref();
    // A symlink is removed itself. `read_link` succeeds only for links; any
    // other error is real and propagates.
    match read_link(path) {
        Ok(_) => return remove_file(path),
        Err(error) if error.kind() == ErrorKind::InvalidInput => {}
        Err(error) => return Err(error),
    }
    let metadata = metadata(path)?;
    if !metadata.is_dir() {
        return Err(Error::from(Errno::ENOTDIR));
    }
    let entries = read_dir(path)?;
    for entry in entries {
        let entry = entry?;
        if entry.file_type().is_dir() {
            remove_dir_all(entry.path())?;
        } else {
            remove_file(entry.path())?;
        }
    }
    remove_dir(path)
}

/// Rename or move `from` to `to` (`renameat2`, flags 0).
pub fn rename<P: AsRef<Path>, Q: AsRef<Path>>(from: P, to: Q) -> Result<()> {
    let from = resolve_path(from.as_ref());
    let to = resolve_path(to.as_ref());
    sys::renameat2(sys::AT_FDCWD, &from, sys::AT_FDCWD, &to, 0)?;
    Ok(())
}

/// Create `new` as a hard link to `existing`.
pub fn hard_link<P: AsRef<Path>, Q: AsRef<Path>>(existing: P, new: Q) -> Result<()> {
    let existing = resolve_path(existing.as_ref());
    let new = resolve_path(new.as_ref());
    sys::linkat(sys::AT_FDCWD, &existing, sys::AT_FDCWD, &new, 0)?;
    Ok(())
}

/// Create a symbolic link at `link_path` whose target is `target`.
///
/// The target is stored verbatim (not resolved), which is the point of a
/// symlink. `link_path` is resolved against the current directory.
pub fn symlink<T: AsRef<Path>, P: AsRef<Path>>(target: T, link_path: P) -> Result<()> {
    let target = target.as_ref();
    let target_text = target.as_str();
    let link = resolve_path(link_path.as_ref());
    // A symlink target may be relative; only the link's own path is resolved.
    sys::symlinkat(target_text, sys::AT_FDCWD, &link)?;
    Ok(())
}

/// Read the target of a symbolic link.
///
/// The ABI does not NUL-terminate the result and does not define a maximum
/// length. This starts at 256 bytes and doubles to 8 KiB, then reports
/// `ENAMETOOLONG`.
pub fn read_link<P: AsRef<Path>>(path: P) -> Result<String> {
    let absolute = resolve_path(path.as_ref());
    let mut capacity = 256usize;
    loop {
        let mut buf = vec![0u8; capacity];
        let n = sys::readlinkat(sys::AT_FDCWD, &absolute, &mut buf)?;
        if n < capacity {
            buf.truncate(n);
            return Ok(String::from_utf8_lossy(&buf).into_owned());
        }
        if capacity >= 8192 {
            return Err(Error::from(Errno::ENAMETOOLONG));
        }
        capacity *= 2;
    }
}

/// Copy `from` to `to`, truncating `to`, and return the bytes copied.
///
/// The destination mode is ext2's default; `copy` does not preserve
/// permissions because the ABI has no durable `chmod`.
pub fn copy<P: AsRef<Path>, Q: AsRef<Path>>(from: P, to: Q) -> Result<u64> {
    let mut source = File::open(from)?;
    let mut destination = File::create(to)?;
    io::copy(&mut source, &mut destination)
}

/// Lexically canonicalize `path`.
///
/// **Lexical only:** the result is absolute and has no `.`/`..` components, but
/// symlinks are not resolved and the path is not required to exist. pagh has no
/// `openat2`/`realpath` and no `AT_SYMLINK_NOFOLLOW`, so a true canonical path
/// would need a `stat` per component and could still race. This is the same
/// documented choice `libpagh::path` makes.
pub fn canonicalize<P: AsRef<Path>>(path: P) -> Result<PathBuf> {
    Ok(PathBuf::from(resolve_path(path.as_ref())))
}

/// Resize a regular file by path.
pub fn truncate<P: AsRef<Path>>(path: P, length: u64) -> Result<()> {
    let file = OpenOptions::new().write(true).open(path)?;
    file.set_len(length)
}

/// Set permission bits (`fchmodat`).
///
/// The current kernel has no `set_mode` in its VFS: it records the bits for the
/// rest of the run and `fstat` reports them, but nothing is written to ext2 and
/// no access check consults the value. A synthetic node such as `/` answers
/// `ENOTSUP`.
pub fn set_permissions<P: AsRef<Path>>(path: P, permissions: Permissions) -> Result<()> {
    let absolute = resolve_path(path.as_ref());
    sys::fchmodat(sys::AT_FDCWD, &absolute, permissions.mode(), 0)?;
    Ok(())
}

/// One entry produced by [`ReadDir`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    path: PathBuf,
    name: String,
    file_type: FileType,
    ino: u64,
}

impl DirEntry {
    /// The full path (parent joined with the name).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The name within its directory (no path, no NUL).
    pub fn file_name(&self) -> &str {
        &self.name
    }

    /// The entry type as recorded by `getdents64` (a symlink is reported as
    /// [`FileType::Symlink`], not as its target).
    pub fn file_type(&self) -> FileType {
        self.file_type
    }

    /// The inode number recorded in the directory entry.
    pub fn ino(&self) -> u64 {
        self.ino
    }

    /// Metadata for the entry.
    ///
    /// This follows symlinks (the ABI has no `lstat`), so it may report the
    /// target's type rather than [`DirEntry::file_type`].
    pub fn metadata(&self) -> Result<Metadata> {
        metadata(&self.path)
    }
}

/// An open directory being read with `getdents64`.
///
/// The kernel snapshots the children at `openat`; the iterator filters `.` and
/// `..`. `Dir` is an alias so both std-shaped spellings work.
pub struct ReadDir {
    fd: i32,
    buf: Vec<u8>,
    start: usize,
    end: usize,
    done: bool,
    root: PathBuf,
}

impl ReadDir {
    /// Open `path` as a directory.
    ///
    /// The entries' [`DirEntry::path`] values are built from the spelling
    /// passed here (std-like), not from the resolved absolute path; the SDK
    /// resolves each of them again when it opens or stats one.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<ReadDir> {
        let root = path.as_ref().to_path_buf();
        let absolute = resolve_path(path.as_ref());
        let file = File::open(absolute.as_str())?;
        Ok(ReadDir {
            fd: file.into_raw_fd(),
            buf: vec![0u8; 4096],
            start: 0,
            end: 0,
            done: false,
            root,
        })
    }

    /// The directory path this iterator was opened on.
    pub fn path(&self) -> &Path {
        &self.root
    }
}

/// Alias for [`ReadDir`], matching the naming used by `libpagh`.
pub type Dir = ReadDir;

impl Iterator for ReadDir {
    type Item = Result<DirEntry>;

    fn next(&mut self) -> Option<Result<DirEntry>> {
        loop {
            if self.done {
                return None;
            }
            if self.start >= self.end {
                match sys::getdents64(self.fd, &mut self.buf) {
                    Ok(0) => {
                        self.done = true;
                        return None;
                    }
                    Ok(n) if n <= self.buf.len() => {
                        self.start = 0;
                        self.end = n;
                    }
                    Ok(_) => {
                        self.done = true;
                        return Some(Err(Error::from(Errno::EIO)));
                    }
                    Err(error) => {
                        self.done = true;
                        return Some(Err(Error::from(error)));
                    }
                }
            }

            let start = self.start;
            let end = self.end;
            let record_len = end - start;
            if record_len < DIRENT_HEADER {
                self.done = true;
                return Some(Err(Error::from(Errno::EIO)));
            }
            let name_len = self.buf[start + 9] as usize;
            let Some(record_size) = dirent_size(name_len) else {
                self.done = true;
                return Some(Err(Error::from(Errno::EIO)));
            };
            if name_len == 0 || record_size > record_len || DIRENT_HEADER + name_len > record_len {
                self.done = true;
                return Some(Err(Error::from(Errno::EIO)));
            }

            let mut raw_ino = [0u8; 8];
            raw_ino.copy_from_slice(&self.buf[start..start + 8]);
            let ino = u64::from_le_bytes(raw_ino);
            let kind = EntryKind::from_raw(self.buf[start + 8] as u32);
            let name = String::from_utf8_lossy(
                &self.buf[start + DIRENT_HEADER..start + DIRENT_HEADER + name_len],
            )
            .into_owned();
            self.start += record_size;

            if name == "." || name == ".." {
                continue;
            }
            if name.contains('/') {
                self.done = true;
                return Some(Err(Error::from(Errno::EIO)));
            }

            return Some(Ok(DirEntry {
                path: self.root.join(name.as_str()),
                name,
                file_type: kind.into(),
                ino,
            }));
        }
    }
}

impl Drop for ReadDir {
    fn drop(&mut self) {
        if self.fd >= 0 {
            let _ = sys::close(self.fd);
        }
    }
}

impl core::fmt::Debug for ReadDir {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReadDir")
            .field("fd", &self.fd)
            .field("root", &self.root)
            .field("done", &self.done)
            .finish()
    }
}

/// Open a directory and iterate its entries (filtering `.` and `..`).
pub fn read_dir<P: AsRef<Path>>(path: P) -> Result<ReadDir> {
    ReadDir::open(path)
}
