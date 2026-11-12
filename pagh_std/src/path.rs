//! UTF-8 paths: `Path`, `PathBuf`, `Component` and lexical normalization.
//!
//! pagh has no `OsStr`, no `AT_SYMLINK_NOFOLLOW` and no per-process kernel
//! working directory. The kernel accepts **absolute** paths only; the SDK
//! resolves relative names against [`env::current_dir`](crate::env::current_dir)
//! and normalizes them lexically before every syscall.
//!
//! This module is deliberately operating-system independent (it only uses
//! `alloc` and `core`), which is what lets it be unit-tested on the host. It
//! never touches the filesystem: `..` is resolved by string manipulation, not
//! by `stat`, so a path that does not exist still normalizes. [`Path`] values
//! are valid UTF-8 by construction; a filename that is not UTF-8 is decoded
//! lossily when a directory is listed (see [`crate::fs`]).
//!
//! The subset is std-shaped: [`Path::join`], [`Path::parent`],
//! [`Path::file_name`], [`Path::file_stem`], [`Path::extension`],
//! [`Path::components`], [`Path::starts_with`], [`Path::strip_prefix`],
//! [`Path::ancestors`], [`Path::display`], `PathBuf::push`/`pop` and the
//! `with_*`/`set_*` mutators. It is not `std::path` byte-for-byte: there is no
//! `OsStr` and no Windows prefix, and [`Path::components`] deliberately yields
//! a `CurDir` for an empty path and for every interior `.` (std yields none for
//! an empty path and skips interior dots), because the normalization helpers
//! read it textually. The query APIs -- `starts_with`, `strip_prefix`,
//! `ancestors`, `parent`, `file_name` and the `*_stem`/`extension` pair -- use
//! a private std-shaped scanner instead, so their edge cases (empty paths,
//! repeated separators, trailing `.` components, `.`/`..`) match std.

use alloc::borrow::Cow;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
use core::hash::{Hash, Hasher};
use core::ops::{Deref, DerefMut};

/// One component of a [`Path`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Component<'a> {
    /// The root directory, `/`.
    RootDir,
    /// The current directory, `.`.
    CurDir,
    /// The parent directory, `..`.
    ParentDir,
    /// A normal component (never empty, never `.` or `..`).
    Normal(&'a str),
}

impl<'a> Component<'a> {
    /// The component's spelling.
    pub fn as_str(self) -> &'a str {
        match self {
            Component::RootDir => "/",
            Component::CurDir => ".",
            Component::ParentDir => "..",
            Component::Normal(name) => name,
        }
    }
}

impl fmt::Display for Component<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Iterator returned by [`Path::components`].
#[derive(Clone, Debug)]
pub struct Components<'a> {
    path: &'a str,
    pos: usize,
    root_done: bool,
    empty_done: bool,
}

impl<'a> Components<'a> {
    fn new(path: &'a str) -> Components<'a> {
        Components {
            path,
            pos: 0,
            root_done: false,
            empty_done: false,
        }
    }

    /// The remaining, not-yet-iterated part of the path.
    pub fn as_path(&self) -> &'a Path {
        Path::new(&self.path[self.pos..])
    }
}

impl<'a> Iterator for Components<'a> {
    type Item = Component<'a>;

    fn next(&mut self) -> Option<Component<'a>> {
        if self.path.is_empty() {
            if self.empty_done {
                return None;
            }
            self.empty_done = true;
            return Some(Component::CurDir);
        }

        if !self.root_done {
            self.root_done = true;
            if self.path.as_bytes().first() == Some(&b'/') {
                while self.path.as_bytes().get(self.pos) == Some(&b'/') {
                    self.pos += 1;
                }
                return Some(Component::RootDir);
            }
        }

        while self.path.as_bytes().get(self.pos) == Some(&b'/') {
            self.pos += 1;
        }
        if self.pos >= self.path.len() {
            return None;
        }
        let start = self.pos;
        while self.pos < self.path.len() && self.path.as_bytes()[self.pos] != b'/' {
            self.pos += 1;
        }
        let component = &self.path[start..self.pos];
        Some(match component {
            "." => Component::CurDir,
            ".." => Component::ParentDir,
            other => Component::Normal(other),
        })
    }
}

/// Iterator returned by [`Path::ancestors`].
#[derive(Clone, Debug)]
pub struct Ancestors<'a> {
    next: Option<&'a Path>,
}

impl<'a> Iterator for Ancestors<'a> {
    type Item = &'a Path;

    fn next(&mut self) -> Option<&'a Path> {
        let current = self.next?;
        // `parent` borrows through `current`, so the item and the next step
        // share the `'a` of the path this iterator was created from.
        self.next = current.parent();
        Some(current)
    }
}

/// Error returned by [`Path::strip_prefix`] when `base` is not a prefix of the
/// path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StripPrefixError(());

impl fmt::Display for StripPrefixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("prefix not found")
    }
}

impl core::error::Error for StripPrefixError {}

/// Component scanner used by [`Path::starts_with`] and [`Path::strip_prefix`].
///
/// [`Components`] yields a `CurDir` for an empty path and for every interior
/// `.`, which is what the normalization code wants but not how `std::path`
/// compares prefixes. This iterator follows `std::path::Components`: an empty
/// path has no components, a `.` is `CurDir` only as the first component of a
/// relative path, every other `.` is skipped, and repeated or trailing `/`
/// disappears. It also tracks the byte position after the last produced
/// component, so `strip_prefix` can return a borrowed remainder.
struct PathTokens<'a> {
    text: &'a str,
    pos: usize,
    started: bool,
}

impl<'a> PathTokens<'a> {
    fn new(text: &'a str) -> PathTokens<'a> {
        PathTokens {
            text,
            pos: 0,
            started: false,
        }
    }
}

impl<'a> Iterator for PathTokens<'a> {
    type Item = Component<'a>;

    fn next(&mut self) -> Option<Component<'a>> {
        let bytes = self.text.as_bytes();
        if !self.started {
            self.started = true;
            if bytes.first() == Some(&b'/') {
                while bytes.get(self.pos) == Some(&b'/') {
                    self.pos += 1;
                }
                return Some(Component::RootDir);
            }
        }
        loop {
            while bytes.get(self.pos) == Some(&b'/') {
                self.pos += 1;
            }
            if self.pos >= bytes.len() {
                return None;
            }
            let start = self.pos;
            while self.pos < bytes.len() && bytes[self.pos] != b'/' {
                self.pos += 1;
            }
            match &self.text[start..self.pos] {
                // A leading `.` survives as `CurDir`; an interior one (`a/./b`)
                // is normalized away, as std does.
                "." if start == 0 => return Some(Component::CurDir),
                "." => continue,
                ".." => return Some(Component::ParentDir),
                other => return Some(Component::Normal(other)),
            }
        }
    }
}

/// The last std-shaped component of `text` and its byte offset.
///
/// Trailing separators and trailing `.` components do not produce a component,
/// so `a/.` ends in `a`, exactly as std's `Components::next_back` sees it.
/// Used by [`Path::parent`] and [`Path::file_name`].
fn last_component(text: &str) -> Option<(Component<'_>, usize)> {
    let mut tokens = PathTokens::new(text);
    let mut last = None;
    while let Some(component) = tokens.next() {
        let end = tokens.pos;
        let start = if component == Component::RootDir {
            0
        } else {
            text[..end].rfind('/').map_or(0, |index| index + 1)
        };
        last = Some((component, start));
    }
    last
}

/// Trim `text[start..end]` the way `std::path::Components::as_path` trims the
/// remainder: trailing separators and trailing `.` components disappear, but a
/// root-only prefix keeps its `/`. Returns the new end offset, never below
/// `start`.
fn trim_component_end(text: &str, start: usize, end: usize) -> usize {
    let bytes = text.as_bytes();
    let mut end = end;
    loop {
        while end > 1 && bytes[end - 1] == b'/' {
            end -= 1;
        }
        if end <= 1 || end <= start {
            break;
        }
        let segment_start = match text[start..end].rfind('/') {
            Some(index) => start + index + 1,
            None => start,
        };
        if &text[segment_start..end] == "." {
            end = segment_start;
            continue;
        }
        break;
    }
    end.max(start)
}

/// A borrowed UTF-8 path.
///
/// `Path` is an unsized type, exactly like `std::path::Path`: construct a
/// reference with [`Path::new`], and own one with [`PathBuf`].
#[repr(transparent)]
pub struct Path(str);

impl Path {
    /// Wrap a string reference as a path without allocating.
    pub fn new<S: AsRef<str> + ?Sized>(s: &S) -> &Path {
        // SAFETY: `Path` is `#[repr(transparent)]` over `str`, so a `&str`
        // and a `&Path` have identical size, alignment and provenance. The
        // borrow is tied to `s` by the signature.
        unsafe { &*(s.as_ref() as *const str as *const Path) }
    }

    /// The path as UTF-8 text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Copy the path into an owned [`PathBuf`].
    pub fn to_path_buf(&self) -> PathBuf {
        PathBuf::from(self.as_str())
    }

    /// True when the path starts with `/`.
    pub fn is_absolute(&self) -> bool {
        self.0.starts_with('/')
    }

    /// True when the path does not start with `/`.
    pub fn is_relative(&self) -> bool {
        !self.is_absolute()
    }

    /// A borrowed version of the path's text.
    ///
    /// Always `Some` in this SDK: paths are UTF-8. The `Option` keeps the
    /// signature compatible with std and with a future `OsStr`.
    pub fn to_str(&self) -> Option<&str> {
        Some(&self.0)
    }

    /// The path as text; never lossy, because it is already UTF-8.
    pub fn to_string_lossy(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.0)
    }

    /// Iterate over the path's components.
    pub fn components(&self) -> Components<'_> {
        Components::new(&self.0)
    }

    /// Iterate over the path's components (alias for [`Path::components`]).
    pub fn iter(&self) -> Components<'_> {
        self.components()
    }

    /// True when `base` is a component-wise prefix of this path.
    ///
    /// `a/b` starts with `a` and with `a/`, but not with `ab`; an absolute
    /// path never starts with a relative one (and vice versa). `.` and `..`
    /// are ordinary components here, so the comparison is lexical, like the
    /// rest of the module, and does not touch the filesystem. The empty path
    /// is a prefix of everything.
    pub fn starts_with<P: AsRef<Path>>(&self, base: P) -> bool {
        let mut remaining = PathTokens::new(self.as_str());
        for expected in PathTokens::new(base.as_ref().as_str()) {
            match remaining.next() {
                Some(component) if component == expected => {}
                _ => return false,
            }
        }
        true
    }

    /// Remove `base` from the front of this path.
    ///
    /// Returns the rest of the path, borrowed from `self` and spelled as it is
    /// there, or [`StripPrefixError`] when `base` is not a component-wise
    /// prefix. The remainder is what std's `Components::as_path` returns:
    /// leading separators and interior `.` components between the prefix and
    /// the remainder are not part of it, and trailing separators or trailing
    /// `.` components are trimmed (`a/b/` stripped of `a/b` is `""`,
    /// `a/./` stripped of `a` is `""`). A prefix that covers the whole path
    /// leaves the empty path; the empty prefix leaves the path with its
    /// trailing separators trimmed (`a/b/` stripped of `""` is `a/b`), which
    /// is also what std returns.
    pub fn strip_prefix<P: AsRef<Path>>(&self, base: P) -> Result<&Path, StripPrefixError> {
        let text = self.as_str();
        let bytes = text.as_bytes();
        let mut remaining = PathTokens::new(text);
        let mut matched = 0usize;
        for expected in PathTokens::new(base.as_ref().as_str()) {
            match remaining.next() {
                Some(component) if component == expected => matched += 1,
                _ => return Err(StripPrefixError(())),
            }
        }
        // Start of the remainder. With a non-empty prefix, `remaining.pos` sits
        // just after the last matched component and the remainder begins at the
        // next real component: separators and interior `.` components between
        // the prefix and it are skipped. The empty prefix consumes nothing, so
        // the whole path (including a leading `/` or `./`) is the remainder.
        let mut start = 0;
        if matched > 0 {
            start = remaining.pos;
            loop {
                while bytes.get(start) == Some(&b'/') {
                    start += 1;
                }
                if start >= bytes.len() {
                    return Ok(Path::new(""));
                }
                let segment_start = start;
                while start < bytes.len() && bytes[start] != b'/' {
                    start += 1;
                }
                if &text[segment_start..start] != "." {
                    start = segment_start;
                    break;
                }
            }
        }
        // Right-trim like std's `Components::as_path`: trailing separators and
        // trailing `.` components are not part of the remainder. A path that
        // is only separators collapses to `/`, never to the empty path.
        let end = trim_component_end(text, start, bytes.len());
        Ok(Path::new(&text[start..end]))
    }

    /// Iterate over this path and its parents, ending with the empty path.
    ///
    /// The first item is `self` (spelled as it is); every following item is
    /// the previous one's [`Path::parent`], so `/a/b` yields `/a/b`, `/a` and
    /// `/`, while `a` yields `a` and `""`, and `""` yields only `""`.
    pub fn ancestors(&self) -> Ancestors<'_> {
        Ancestors { next: Some(self) }
    }

    /// Append `path` to this one.
    ///
    /// An absolute `path` replaces the receiver, matching std. The result is
    /// not normalized: `Path::new("a").join("..")` is `a/..`. The filesystem
    /// layer normalizes before it calls the kernel.
    pub fn join<P: AsRef<Path>>(&self, path: P) -> PathBuf {
        let mut buf = self.to_path_buf();
        buf.push(path);
        buf
    }

    /// The path without its final component.
    ///
    /// `None` for `/`, `""` and a path that is only `/`s; `Some("")` for a
    /// single relative component, as std does. Trailing separators and trailing
    /// `.` components are not components, so `a/.` has parent `""` and
    /// `/a/./b` has parent `/a`, exactly like std.
    pub fn parent(&self) -> Option<&Path> {
        let text = self.as_str();
        match last_component(text)? {
            (Component::Normal(_) | Component::CurDir | Component::ParentDir, start) => {
                let end = trim_component_end(text, 0, start);
                Some(Path::new(&text[..end]))
            }
            (Component::RootDir, _) => None,
        }
    }

    /// The final component, unless it is `/`, `.` or `..`.
    ///
    /// This is std's `components().next_back()`: trailing separators and
    /// trailing `.` components are skipped (`a/./` names `a`).
    pub fn file_name(&self) -> Option<&str> {
        match last_component(self.as_str())? {
            (Component::Normal(name), _) => Some(name),
            _ => None,
        }
    }

    /// The file name without its final extension.
    pub fn file_stem(&self) -> Option<&str> {
        let name = self.file_name()?;
        match self.extension() {
            // `extension` is `Some` only when the dot is not the first byte,
            // so `dot` is a valid slice boundary and is > 0.
            Some(_) => match name.rfind('.') {
                Some(dot) => Some(&name[..dot]),
                None => Some(name),
            },
            None => Some(name),
        }
    }

    /// The text after the final `.` of the file name.
    ///
    /// A leading dot does not start an extension: `.bashrc` has none. A
    /// trailing dot is an empty extension (`Some("")`).
    pub fn extension(&self) -> Option<&str> {
        let name = self.file_name()?;
        let dot = name.rfind('.')?;
        if dot == 0 {
            None
        } else {
            Some(&name[dot + 1..])
        }
    }

    /// Replace the extension. Returns a new path; see [`PathBuf::set_extension`].
    pub fn with_extension<S: AsRef<str>>(&self, extension: S) -> PathBuf {
        let mut buf = self.to_path_buf();
        buf.set_extension(extension);
        buf
    }

    /// Replace the file name. Returns a new path; see [`PathBuf::set_file_name`].
    pub fn with_file_name<S: AsRef<str>>(&self, file_name: S) -> PathBuf {
        let mut buf = self.to_path_buf();
        buf.set_file_name(file_name);
        buf
    }

    /// A `Display` adapter for the path.
    ///
    /// `Path` also implements `Display` directly in this SDK (all paths are
    /// UTF-8), but `display()` is kept because std code uses it.
    pub fn display(&self) -> Display<'_> {
        Display { path: self }
    }
}

impl AsRef<Path> for Path {
    fn as_ref(&self) -> &Path {
        self
    }
}

impl AsRef<str> for Path {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<Path> for str {
    fn as_ref(&self) -> &Path {
        Path::new(self)
    }
}

impl AsRef<Path> for String {
    fn as_ref(&self) -> &Path {
        Path::new(self)
    }
}

impl PartialEq for Path {
    fn eq(&self, other: &Path) -> bool {
        self.0 == other.0
    }
}

impl Eq for Path {}

impl PartialOrd for Path {
    fn partial_cmp(&self, other: &Path) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Path {
    fn cmp(&self, other: &Path) -> core::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl Hash for Path {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl PartialEq<PathBuf> for Path {
    fn eq(&self, other: &PathBuf) -> bool {
        self == other.as_path()
    }
}

impl PartialEq<Path> for PathBuf {
    fn eq(&self, other: &Path) -> bool {
        self.as_path() == other
    }
}

impl fmt::Debug for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// `Display` adapter returned by [`Path::display`].
#[derive(Clone, Copy, Debug)]
pub struct Display<'a> {
    path: &'a Path,
}

impl fmt::Display for Display<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.path.as_str())
    }
}

/// An owned UTF-8 path.
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PathBuf {
    inner: String,
}

impl PathBuf {
    /// A new empty path.
    pub const fn new() -> PathBuf {
        PathBuf {
            inner: String::new(),
        }
    }

    /// The path as a borrowed [`Path`].
    pub fn as_path(&self) -> &Path {
        Path::new(self.inner.as_str())
    }

    /// Consume the path and return its string.
    pub fn into_string(self) -> String {
        self.inner
    }

    /// Append a component.
    ///
    /// An absolute component replaces the whole path. An empty component is a
    /// no-op. A separator is inserted only when needed.
    pub fn push<P: AsRef<Path>>(&mut self, path: P) {
        let text = path.as_ref().as_str();
        if text.is_empty() {
            return;
        }
        if text.starts_with('/') {
            self.inner.clear();
            self.inner.push_str(text);
            return;
        }
        if !self.inner.is_empty() && !self.inner.ends_with('/') {
            self.inner.push('/');
        }
        self.inner.push_str(text);
    }

    /// Remove the final component. Returns `false` for `/` and an empty path.
    pub fn pop(&mut self) -> bool {
        if self.inner.is_empty() || self.inner == "/" {
            return false;
        }
        let parent = self
            .as_path()
            .parent()
            .map(|path| path.as_str().to_string());
        match parent {
            Some(parent) => {
                self.inner = parent;
                true
            }
            None => false,
        }
    }

    /// Replace the file name, keeping the parent directory.
    pub fn set_file_name<S: AsRef<str>>(&mut self, file_name: S) {
        let name = file_name.as_ref();
        if self.as_path().file_name().is_some() {
            let parent = match self.as_path().parent() {
                Some(parent) => parent.as_str().to_string(),
                None => String::new(),
            };
            self.inner = parent;
        }
        self.push(name);
    }

    /// Replace or remove the extension.
    ///
    /// An empty extension removes the dot; a path with no file name is left
    /// unchanged.
    pub fn set_extension<S: AsRef<str>>(&mut self, extension: S) {
        let Some(name) = self.as_path().file_name().map(str::to_string) else {
            return;
        };
        let stem_end = if self.as_path().extension().is_some() {
            match name.rfind('.') {
                Some(dot) => dot,
                None => name.len(),
            }
        } else {
            name.len()
        };
        let mut replacement = String::from(&name[..stem_end]);
        let extension = extension.as_ref();
        if !extension.is_empty() {
            replacement.push('.');
            replacement.push_str(extension);
        }
        self.set_file_name(replacement);
    }

    /// Ensure the path is absolute by resolving it against `base`.
    ///
    /// This is lexical only (no filesystem access); see [`normalize_join`].
    pub fn resolve_from(&self, base: &str) -> PathBuf {
        PathBuf::from(normalize_join(base, self.as_str()))
    }

    /// Normalize the path lexically (see [`normalize`]).
    pub fn normalize(&self) -> PathBuf {
        PathBuf::from(normalize(self.as_str()))
    }
}

impl Deref for PathBuf {
    type Target = Path;

    fn deref(&self) -> &Path {
        self.as_path()
    }
}

impl DerefMut for PathBuf {
    fn deref_mut(&mut self) -> &mut Path {
        // SAFETY: `PathBuf` is a `String` and `Path` is `#[repr(transparent)]`
        // over `str`. Converting `&mut String` to `&mut Path` is the same
        // layout and provenance, and the `String` remains valid UTF-8 because
        // `Path` exposes no mutation API.
        unsafe { &mut *(self.inner.as_mut_str() as *mut str as *mut Path) }
    }
}

impl AsRef<Path> for PathBuf {
    fn as_ref(&self) -> &Path {
        self.as_path()
    }
}

impl AsRef<str> for PathBuf {
    fn as_ref(&self) -> &str {
        self.inner.as_str()
    }
}

impl core::borrow::Borrow<Path> for PathBuf {
    fn borrow(&self) -> &Path {
        self.as_path()
    }
}

impl From<&str> for PathBuf {
    fn from(value: &str) -> PathBuf {
        PathBuf {
            inner: String::from(value),
        }
    }
}

impl From<String> for PathBuf {
    fn from(value: String) -> PathBuf {
        PathBuf { inner: value }
    }
}

impl From<&Path> for PathBuf {
    fn from(value: &Path) -> PathBuf {
        PathBuf::from(value.as_str())
    }
}

impl From<&PathBuf> for PathBuf {
    fn from(value: &PathBuf) -> PathBuf {
        value.clone()
    }
}

impl From<PathBuf> for String {
    fn from(value: PathBuf) -> String {
        value.inner
    }
}

impl fmt::Debug for PathBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.inner.as_str(), f)
    }
}

impl fmt::Display for PathBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.inner)
    }
}

/// Normalize `path` without touching the filesystem.
///
/// * collapse repeated `/` and drop `.` components;
/// * resolve `..` against the previous component; at the root, extra `..` is
///   dropped (there is no way above `/`);
/// * a relative path keeps a leading `..` (there is no parent to pop);
/// * `""` becomes `"."`; an absolute path that collapses becomes `"/"`.
///
/// The result has no trailing slash except `/` itself.
pub fn normalize(path: &str) -> String {
    let absolute = path.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => match parts.last() {
                Some(last) if *last != ".." => {
                    parts.pop();
                }
                Some(_) => {
                    if !absolute {
                        parts.push("..");
                    }
                }
                None => {
                    if !absolute {
                        parts.push("..");
                    }
                }
            },
            other => parts.push(other),
        }
    }

    if parts.is_empty() {
        return if absolute {
            String::from("/")
        } else {
            String::from(".")
        };
    }

    let mut out = String::with_capacity(path.len() + 1);
    if absolute {
        out.push('/');
    }
    for (index, part) in parts.iter().enumerate() {
        if index > 0 {
            out.push('/');
        }
        out.push_str(part);
    }
    out
}

/// Join `path` onto `base` and normalize, unless `path` is already absolute.
///
/// This is the one function the filesystem layer uses to turn a user-provided
/// path into the absolute path the kernel requires. `base` itself is not
/// assumed to be normalized.
pub fn normalize_join(base: &str, path: &str) -> String {
    if path.starts_with('/') {
        return normalize(path);
    }
    if base.is_empty() {
        return normalize(path);
    }
    let mut joined = String::with_capacity(base.len() + path.len() + 2);
    joined.push_str(base);
    if !base.ends_with('/') {
        joined.push('/');
    }
    joined.push_str(path);
    normalize(&joined)
}
