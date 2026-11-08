//! Byte-oriented I/O: the `Read`/`Write`/`Seek`/`BufRead` traits, buffered
//! adapters and the three console handles.
//!
//! This is a practical subset of `std::io`, not a reimplementation of it. The
//! traits use the SDK's [`Error`] (which preserves the ABI's [`Errno`]) and
//! operate directly on the frozen syscall table:
//!
//! * [`File`](crate::fs::File) is one unbuffered `read`/`write`/`lseek` per
//!   method call on the normal path; its direct `BufRead` implementation reads
//!   ahead into an 8 KiB buffer only when `fill_buf` is used;
//! * [`BufReader`] and [`BufWriter`] add userland buffering;
//! * [`stdin`] blocks by retrying `EAGAIN` with `sched_yield`. The kernel's
//!   console `read(0)` is non-blocking; this handle keeps its historical yield
//!   loop (the `poll` wrapper is available separately). The console has **no
//!   EOF**: `cat` with no arguments waits forever.
//!
//! There is no `Cursor`, `Chain`, `Tee`, file locking or vectored I/O in this
//! version; every one of those would be a userland-only convenience, and the
//! SDK keeps the surface it can test on the real kernel.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use libpagh::errno::Errno;
use libpagh::sys;

pub use crate::error::{Error, ErrorKind, Result};
pub use libpagh::io::SeekFrom;

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

/// A byte source.
pub trait Read {
    /// Read up to `buf.len()` bytes into `buf`.
    ///
    /// `Ok(0)` means end of file. A short read is normal and must not be
    /// treated as EOF.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;

    /// Read until end of file, appending every byte to `buf`.
    ///
    /// Uses `try_reserve`, so running out of the 1 MiB `brk` heap is
    /// [`ErrorKind::OutOfMemory`], not an allocator abort.
    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> Result<usize> {
        let start = buf.len();
        let mut chunk = [0u8; 4096];
        loop {
            let n = self.read(&mut chunk)?;
            if n == 0 {
                return Ok(buf.len() - start);
            }
            if n > chunk.len() {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "reader returned more bytes than the buffer holds",
                ));
            }
            buf.try_reserve(n).map_err(|_| Error::from(Errno::ENOMEM))?;
            buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// Read until end of file, appending UTF-8 text to `buf`.
    ///
    /// The bytes are validated **before** `buf` is modified: a file that is
    /// not UTF-8 leaves the destination untouched and returns
    /// [`ErrorKind::InvalidData`]. The ABI has no `EILSEQ`, so the SDK uses
    /// the std-shaped `InvalidData` class.
    fn read_to_string(&mut self, buf: &mut String) -> Result<usize> {
        let mut bytes = Vec::new();
        let n = self.read_to_end(&mut bytes)?;
        let text = core::str::from_utf8(&bytes).map_err(|_| {
            Error::new(ErrorKind::InvalidData, "stream did not contain valid UTF-8")
        })?;
        buf.try_reserve(text.len())
            .map_err(|_| Error::from(Errno::ENOMEM))?;
        buf.push_str(text);
        Ok(n)
    }

    /// Fill all of `buf`, or fail with [`ErrorKind::UnexpectedEof`].
    fn read_exact(&mut self, mut buf: &mut [u8]) -> Result<()> {
        while !buf.is_empty() {
            match self.read(buf) {
                Ok(0) => {
                    return Err(Error::new(
                        ErrorKind::UnexpectedEof,
                        "failed to fill whole buffer",
                    ))
                }
                Ok(n) if n <= buf.len() => buf = &mut buf[n..],
                Ok(_) => {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "reader returned more bytes than the buffer holds",
                    ))
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Adapt this reader into an iterator over individual bytes.
    fn bytes(self) -> Bytes<Self>
    where
        Self: Sized,
    {
        Bytes { inner: self }
    }

    /// Borrow the reader for a call that expects `Read`.
    fn by_ref(&mut self) -> &mut Self
    where
        Self: Sized,
    {
        self
    }

    /// Read at most `limit` bytes from this reader.
    fn take(self, limit: u64) -> Take<Self>
    where
        Self: Sized,
    {
        Take { inner: self, limit }
    }
}

impl Read for &[u8] {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let n = core::cmp::min(self.len(), buf.len());
        buf[..n].copy_from_slice(&self[..n]);
        *self = &self[n..];
        Ok(n)
    }
}

impl<R: Read + ?Sized> Read for &mut R {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        (**self).read(buf)
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> Result<usize> {
        (**self).read_to_end(buf)
    }

    fn read_to_string(&mut self, buf: &mut String) -> Result<usize> {
        (**self).read_to_string(buf)
    }
}

/// Iterator returned by [`Read::bytes`].
#[derive(Debug)]
pub struct Bytes<R> {
    inner: R,
}

impl<R: Read> Iterator for Bytes<R> {
    type Item = Result<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut byte = [0u8; 1];
        match self.inner.read(&mut byte) {
            Ok(0) => None,
            Ok(_) => Some(Ok(byte[0])),
            Err(error) => Some(Err(error)),
        }
    }
}

/// Reader returned by [`Read::take`]; it reports EOF after `limit` bytes.
#[derive(Debug)]
pub struct Take<R> {
    inner: R,
    limit: u64,
}

impl<R> Take<R> {
    /// The number of bytes this reader may still return.
    pub fn limit(&self) -> u64 {
        self.limit
    }

    /// Give the wrapped reader back.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for Take<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.limit == 0 {
            return Ok(0);
        }
        let max = core::cmp::min(buf.len() as u64, self.limit) as usize;
        let n = self.inner.read(&mut buf[..max])?;
        self.limit = self.limit.saturating_sub(n as u64);
        Ok(n)
    }
}

// ---------------------------------------------------------------------------
// Write
// ---------------------------------------------------------------------------

/// A byte sink.
pub trait Write {
    /// Write up to `buf.len()` bytes; a short write is possible.
    fn write(&mut self, buf: &[u8]) -> Result<usize>;

    /// Flush buffered data. Unbuffered writers return `Ok(())`.
    fn flush(&mut self) -> Result<()>;

    /// Write every byte of `buf`, looping over short writes.
    fn write_all(&mut self, mut buf: &[u8]) -> Result<()> {
        while !buf.is_empty() {
            match self.write(buf) {
                Ok(0) => {
                    return Err(Error::new(
                        ErrorKind::WriteZero,
                        "failed to write whole buffer",
                    ))
                }
                Ok(n) if n <= buf.len() => buf = &buf[n..],
                Ok(_) => {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "writer claimed to write more bytes than it was given",
                    ))
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Format arguments into this writer; this is what `write!` calls.
    fn write_fmt(&mut self, args: fmt::Arguments<'_>) -> Result<()> {
        let mut adapter = Adapter { inner: self };
        fmt::write(&mut adapter, args).map_err(|_| Error::new(ErrorKind::Other, "formatter error"))
    }

    /// Borrow the writer for a call that expects `Write`.
    fn by_ref(&mut self) -> &mut Self
    where
        Self: Sized,
    {
        self
    }
}

impl<W: Write + ?Sized> Write for &mut W {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        (**self).write(buf)
    }

    fn flush(&mut self) -> Result<()> {
        (**self).flush()
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        (**self).write_all(buf)
    }

    fn write_fmt(&mut self, args: fmt::Arguments<'_>) -> Result<()> {
        (**self).write_fmt(args)
    }
}

/// The `fmt::Write` bridge used by [`Write::write_fmt`].
struct Adapter<'a, W: ?Sized> {
    inner: &'a mut W,
}

impl<W: Write + ?Sized> fmt::Write for Adapter<'_, W> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.inner.write_all(s.as_bytes()).map_err(|_| fmt::Error)
    }
}

// ---------------------------------------------------------------------------
// Seek
// ---------------------------------------------------------------------------

/// A seekable byte source/sink (regular files).
pub trait Seek {
    /// Move the offset and return the new absolute offset.
    fn seek(&mut self, pos: SeekFrom) -> Result<u64>;

    /// The current offset (`seek(Current(0))`).
    fn stream_position(&mut self) -> Result<u64> {
        self.seek(SeekFrom::Current(0))
    }

    /// Seek back to the start.
    fn rewind(&mut self) -> Result<()> {
        self.seek(SeekFrom::Start(0)).map(|_| ())
    }

    /// Seek relative to the current position.
    fn seek_relative(&mut self, offset: i64) -> Result<()> {
        self.seek(SeekFrom::Current(offset)).map(|_| ())
    }
}

impl<S: Seek + ?Sized> Seek for &mut S {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
        (**self).seek(pos)
    }
}

// ---------------------------------------------------------------------------
// BufRead
// ---------------------------------------------------------------------------

/// A buffered byte source.
pub trait BufRead: Read {
    /// Return the buffered bytes without consuming them.
    ///
    /// An empty slice means end of file.
    fn fill_buf(&mut self) -> Result<&[u8]>;

    /// Mark `amt` bytes of the last [`fill_buf`](BufRead::fill_buf) slice as
    /// consumed. `amt` is clamped to the available bytes rather than panicking.
    fn consume(&mut self, amt: usize);

    /// Read through the first `byte` (inclusive), appending to `buf`.
    fn read_until(&mut self, byte: u8, buf: &mut Vec<u8>) -> Result<usize> {
        let mut read = 0usize;
        loop {
            let (found, used) = {
                let available = self.fill_buf()?;
                if available.is_empty() {
                    return Ok(read);
                }
                match available.iter().position(|b| *b == byte) {
                    Some(index) => {
                        append_checked(buf, &available[..=index])?;
                        (true, index + 1)
                    }
                    None => {
                        append_checked(buf, available)?;
                        (false, available.len())
                    }
                }
            };
            self.consume(used);
            read = read.saturating_add(used);
            if found {
                return Ok(read);
            }
        }
    }

    /// Read one line, including its trailing `\n`, into `buf`.
    ///
    /// Invalid UTF-8 leaves `buf` untouched and returns
    /// [`ErrorKind::InvalidData`].
    fn read_line(&mut self, buf: &mut String) -> Result<usize> {
        let mut bytes = Vec::new();
        let n = self.read_until(b'\n', &mut bytes)?;
        let text = core::str::from_utf8(&bytes).map_err(|_| {
            Error::new(ErrorKind::InvalidData, "stream did not contain valid UTF-8")
        })?;
        buf.try_reserve(text.len())
            .map_err(|_| Error::from(Errno::ENOMEM))?;
        buf.push_str(text);
        Ok(n)
    }

    /// Iterate over lines, stripping `\n` and a preceding `\r`.
    fn lines(self) -> Lines<Self>
    where
        Self: Sized,
    {
        Lines { inner: self }
    }

    /// Iterate over the pieces separated by `byte`; the separator is stripped.
    fn split(self, byte: u8) -> Split<Self>
    where
        Self: Sized,
    {
        Split {
            inner: self,
            delim: byte,
        }
    }
}

impl<B: BufRead + ?Sized> BufRead for &mut B {
    fn fill_buf(&mut self) -> Result<&[u8]> {
        (**self).fill_buf()
    }

    fn consume(&mut self, amt: usize) {
        (**self).consume(amt)
    }
}

fn append_checked(buf: &mut Vec<u8>, data: &[u8]) -> Result<()> {
    buf.try_reserve(data.len())
        .map_err(|_| Error::from(Errno::ENOMEM))?;
    buf.extend_from_slice(data);
    Ok(())
}

/// Iterator returned by [`BufRead::lines`].
#[derive(Debug)]
pub struct Lines<B> {
    inner: B,
}

impl<B: BufRead> Iterator for Lines<B> {
    type Item = Result<String>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut line = String::new();
        match self.inner.read_line(&mut line) {
            Ok(0) => None,
            Ok(_) => {
                if line.ends_with('\n') {
                    line.pop();
                    if line.ends_with('\r') {
                        line.pop();
                    }
                }
                Some(Ok(line))
            }
            Err(error) => Some(Err(error)),
        }
    }
}

/// Iterator returned by [`BufRead::split`].
#[derive(Debug)]
pub struct Split<B> {
    inner: B,
    delim: u8,
}

impl<B: BufRead> Iterator for Split<B> {
    type Item = Result<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut buf = Vec::new();
        match self.inner.read_until(self.delim, &mut buf) {
            Ok(0) => None,
            Ok(_) => {
                if buf.last() == Some(&self.delim) {
                    buf.pop();
                }
                Some(Ok(buf))
            }
            Err(error) => Some(Err(error)),
        }
    }
}

// ---------------------------------------------------------------------------
// Internal read-ahead buffer
// ---------------------------------------------------------------------------

/// Read-ahead storage used by [`BufRead`] implementations on concrete types.
///
/// `std` implements `BufRead` for `BufReader`, not for `File` or `TcpStream`.
/// pagh_std implements the trait directly on those types (see their module
/// docs); this is the small buffer behind that choice. It is allocated lazily,
/// only when `fill_buf` is first called, so programs that use the unbuffered
/// `Read` path do not pay for it.
pub(crate) struct ReadBuffer {
    buf: Vec<u8>,
    pos: usize,
    cap: usize,
}

impl ReadBuffer {
    pub(crate) const fn new() -> ReadBuffer {
        ReadBuffer {
            buf: Vec::new(),
            pos: 0,
            cap: 0,
        }
    }

    /// Bytes buffered but not consumed.
    pub(crate) fn unread(&self) -> usize {
        self.cap - self.pos
    }

    /// The buffered bytes, without reading further.
    pub(crate) fn buffered(&self) -> &[u8] {
        &self.buf[self.pos..self.cap]
    }

    /// Drop all buffered bytes (the underlying object handles any repositioning).
    pub(crate) fn discard(&mut self) {
        self.pos = 0;
        self.cap = 0;
    }

    /// Mark `amt` buffered bytes consumed, clamped to what is present.
    pub(crate) fn consume(&mut self, amt: usize) {
        self.pos += core::cmp::min(amt, self.unread());
    }

    /// `Read` through the buffer.
    ///
    /// An empty buffer makes this a direct call; otherwise the request is
    /// served from the current buffered slice. `read_raw` is only invoked when
    /// no read-ahead bytes are pending.
    pub(crate) fn read<F>(&mut self, out: &mut [u8], read_raw: F) -> Result<usize>
    where
        F: FnOnce(&mut [u8]) -> Result<usize>,
    {
        if out.is_empty() {
            return Ok(0);
        }
        if self.pos < self.cap {
            let n = core::cmp::min(out.len(), self.unread());
            out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
            self.pos += n;
            return Ok(n);
        }
        read_raw(out)
    }

    /// Refill if empty and return the readable window.
    pub(crate) fn fill<F>(&mut self, read_raw: F) -> Result<&[u8]>
    where
        F: FnOnce(&mut [u8]) -> Result<usize>,
    {
        if self.pos >= self.cap {
            self.pos = 0;
            self.cap = 0;
            if self.buf.is_empty() {
                self.buf = vec![0u8; DEFAULT_BUFFER_SIZE];
            }
            let n = read_raw(&mut self.buf)?;
            if n > self.buf.len() {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "reader returned more bytes than the buffer holds",
                ));
            }
            self.cap = n;
        }
        Ok(&self.buf[self.pos..self.cap])
    }
}

// ---------------------------------------------------------------------------
// Buffered adapters
// ---------------------------------------------------------------------------

/// Default buffer size for [`BufReader`] and [`BufWriter`].
pub const DEFAULT_BUFFER_SIZE: usize = 8192;

/// A `Read` adapter that reads through an internal buffer.
#[derive(Debug)]
pub struct BufReader<R> {
    inner: R,
    buf: Vec<u8>,
    pos: usize,
    cap: usize,
}

impl<R: Read> BufReader<R> {
    /// Wrap `inner` with the default 8 KiB buffer.
    pub fn new(inner: R) -> BufReader<R> {
        Self::with_capacity(DEFAULT_BUFFER_SIZE, inner)
    }

    /// Wrap `inner` with a buffer of `capacity` bytes (at least one).
    pub fn with_capacity(capacity: usize, inner: R) -> BufReader<R> {
        let capacity = capacity.max(1);
        BufReader {
            inner,
            buf: vec![0u8; capacity],
            pos: 0,
            cap: 0,
        }
    }

    /// The buffer capacity in bytes.
    pub fn capacity(&self) -> usize {
        self.buf.len()
    }

    /// The bytes currently buffered and not yet consumed.
    pub fn buffer(&self) -> &[u8] {
        &self.buf[self.pos..self.cap]
    }

    /// Give the wrapped reader back, discarding unread buffered bytes.
    pub fn into_inner(self) -> R {
        self.inner
    }

    /// A shared reference to the wrapped reader.
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// A mutable reference to the wrapped reader.
    ///
    /// Reading from it while bytes are buffered changes the stream position in
    /// a way this adapter cannot observe; use [`BufReader::into_inner`] when
    /// handing the reader over.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }
}

impl<R: Read> Read for BufReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.pos >= self.cap {
            // Bypass the buffer for large reads: copying through it would be
            // pure overhead.
            if buf.len() >= self.buf.len() {
                return self.inner.read(buf);
            }
            self.pos = 0;
            self.cap = 0;
            let n = self.inner.read(&mut self.buf)?;
            self.cap = n;
            if n == 0 {
                return Ok(0);
            }
        }
        let n = core::cmp::min(buf.len(), self.cap - self.pos);
        buf[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl<R: Read> BufRead for BufReader<R> {
    fn fill_buf(&mut self) -> Result<&[u8]> {
        if self.pos >= self.cap {
            self.pos = 0;
            self.cap = self.inner.read(&mut self.buf)?;
        }
        Ok(&self.buf[self.pos..self.cap])
    }

    fn consume(&mut self, amt: usize) {
        let available = self.cap - self.pos;
        self.pos += core::cmp::min(amt, available);
    }
}

impl<R: Seek> Seek for BufReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
        let unread = (self.cap - self.pos) as i64;
        self.pos = 0;
        self.cap = 0;
        match pos {
            // The underlying descriptor is `unread` bytes ahead of the logical
            // position, so a relative seek must subtract those bytes.
            SeekFrom::Current(delta) => self.inner.seek(SeekFrom::Current(delta - unread)),
            other => self.inner.seek(other),
        }
    }
}

/// A `Write` adapter that batches bytes into an internal buffer.
#[derive(Debug)]
pub struct BufWriter<W: Write> {
    inner: W,
    buf: Vec<u8>,
}

impl<W: Write> BufWriter<W> {
    /// Wrap `inner` with the default 8 KiB buffer.
    pub fn new(inner: W) -> BufWriter<W> {
        Self::with_capacity(DEFAULT_BUFFER_SIZE, inner)
    }

    /// Wrap `inner` with a buffer of `capacity` bytes (at least one).
    pub fn with_capacity(capacity: usize, inner: W) -> BufWriter<W> {
        BufWriter {
            inner,
            buf: Vec::with_capacity(capacity.max(1)),
        }
    }

    /// The buffer capacity in bytes.
    pub fn capacity(&self) -> usize {
        self.buf.capacity()
    }

    /// The bytes waiting to be written.
    pub fn buffer(&self) -> &[u8] {
        &self.buf
    }

    /// A shared reference to the wrapped writer.
    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    /// A mutable reference to the wrapped writer.
    ///
    /// Writing directly bypasses the buffer and can reorder output; flush
    /// first unless that is what you want.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Flush and return the wrapped writer.
    pub fn into_inner(mut self) -> Result<W> {
        self.flush()?;
        // SAFETY: `self.inner` is moved bitwise into `inner`; `mem::forget`
        // below suppresses the destructor, so the value is neither dropped
        // twice nor used through `self` after the move. The buffer was flushed
        // first, and `W` is a plain owned value with no self-references.
        let inner = unsafe { core::ptr::read(&self.inner) };
        core::mem::forget(self);
        Ok(inner)
    }

    fn flush_buf(&mut self) -> Result<()> {
        let mut written = 0usize;
        let result = loop {
            if written >= self.buf.len() {
                break Ok(());
            }
            match self.inner.write(&self.buf[written..]) {
                Ok(0) => break Err(Error::new(ErrorKind::WriteZero, "failed to write buffer")),
                Ok(n) => written += n,
                Err(error) => break Err(error),
            }
        };
        if written > 0 {
            self.buf.drain(..written);
        }
        result
    }
}

impl<W: Write> Write for BufWriter<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.buf.len().saturating_add(buf.len()) > self.buf.capacity() {
            self.flush_buf()?;
        }
        if buf.len() >= self.buf.capacity() {
            // Large write: skip the copy and write through.
            return self.inner.write(buf);
        }
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<()> {
        self.flush_buf()?;
        self.inner.flush()
    }
}

impl<W: Write> Drop for BufWriter<W> {
    fn drop(&mut self) {
        // There is nowhere to report an error from `drop`; an explicit
        // `flush()` before dropping is how a program notices a failed write.
        let _ = self.flush_buf();
    }
}

// ---------------------------------------------------------------------------
// Console handles
// ---------------------------------------------------------------------------

/// Console input, fd 0.
///
/// `read` blocks by retrying `EAGAIN` with `sched_yield`; see the module docs
/// for the absence of EOF.
#[derive(Clone, Copy, Debug, Default)]
pub struct Stdin;

/// Console output, fd 1.
#[derive(Clone, Copy, Debug, Default)]
pub struct Stdout;

/// Console diagnostics, fd 2.
#[derive(Clone, Copy, Debug, Default)]
pub struct Stderr;

impl Stdin {
    /// A reader for fd 0.
    pub const fn new() -> Stdin {
        Stdin
    }
}

impl Stdout {
    /// A writer for fd 1.
    pub const fn new() -> Stdout {
        Stdout
    }
}

impl Stderr {
    /// A writer for fd 2.
    pub const fn new() -> Stderr {
        Stderr
    }
}

impl Read for Stdin {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            match sys::read(0, buf) {
                Ok(n) => return Ok(n),
                Err(Errno::EAGAIN) => {
                    // Keep the console reader's historical yield loop; the
                    // `poll` wrapper is available for callers that want it.
                    let _ = sys::sched_yield();
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
}

impl Write for Stdout {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        write_fd(1, buf)
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

impl Write for Stderr {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        write_fd(2, buf)
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

/// The process's standard input handle.
pub fn stdin() -> Stdin {
    Stdin
}

/// The process's standard output handle.
pub fn stdout() -> Stdout {
    Stdout
}

/// The process's standard error handle.
pub fn stderr() -> Stderr {
    Stderr
}

fn write_fd(fd: i32, buf: &[u8]) -> Result<usize> {
    loop {
        match sys::write(fd, buf) {
            Ok(n) => return Ok(n),
            Err(Errno::EAGAIN) => {
                let _ = sys::sched_yield();
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn write_all_fd(fd: i32, mut buf: &[u8]) -> Result<()> {
    while !buf.is_empty() {
        match write_fd(fd, buf) {
            Ok(0) => {
                return Err(Error::new(
                    ErrorKind::WriteZero,
                    "console write made no progress",
                ))
            }
            Ok(n) if n <= buf.len() => buf = &buf[n..],
            Ok(_) => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "console write claimed more bytes than given",
                ))
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

struct FdWriter(i32);

impl fmt::Write for FdWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        write_all_fd(self.0, s.as_bytes()).map_err(|_| fmt::Error)
    }
}

/// Backing function for `print!`; not part of the stable surface.
#[doc(hidden)]
pub fn _print(args: fmt::Arguments<'_>) {
    let mut writer = FdWriter(1);
    let _ = fmt::write(&mut writer, args);
}

/// Backing function for `eprint!`; not part of the stable surface.
#[doc(hidden)]
pub fn _eprint(args: fmt::Arguments<'_>) {
    let mut writer = FdWriter(2);
    let _ = fmt::write(&mut writer, args);
}

// ---------------------------------------------------------------------------
// Free functions and trivial adapters
// ---------------------------------------------------------------------------

/// Read all bytes from `reader`.
pub fn read_to_end<R: Read + ?Sized>(reader: &mut R) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Read all bytes from `reader` and validate them as UTF-8.
pub fn read_to_string<R: Read + ?Sized>(reader: &mut R) -> Result<String> {
    let mut text = String::new();
    reader.read_to_string(&mut text)?;
    Ok(text)
}

/// Copy `reader` into `writer` until EOF, returning the bytes copied.
pub fn copy<R: Read + ?Sized, W: Write + ?Sized>(reader: &mut R, writer: &mut W) -> Result<u64> {
    let mut buf = [0u8; DEFAULT_BUFFER_SIZE];
    let mut total = 0u64;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            return Ok(total);
        }
        if n > buf.len() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "reader returned more bytes than the buffer holds",
            ));
        }
        writer.write_all(&buf[..n])?;
        total = total
            .checked_add(n as u64)
            .ok_or(Error::from(Errno::EOVERFLOW))?;
    }
}

/// A reader that is always at end of file.
#[derive(Clone, Copy, Debug, Default)]
pub struct Empty;

impl Read for Empty {
    fn read(&mut self, _buf: &mut [u8]) -> Result<usize> {
        Ok(0)
    }
}

/// A reader that yields `byte` forever.
#[derive(Clone, Copy, Debug, Default)]
pub struct Repeat {
    byte: u8,
}

impl Repeat {
    /// A reader of endless `byte`s.
    pub const fn new(byte: u8) -> Repeat {
        Repeat { byte }
    }
}

impl Read for Repeat {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        for slot in buf.iter_mut() {
            *slot = self.byte;
        }
        Ok(buf.len())
    }
}

/// A writer that discards everything and never fails.
#[derive(Clone, Copy, Debug, Default)]
pub struct Sink;

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

/// An empty reader.
pub fn empty() -> Empty {
    Empty
}

/// A reader of infinite repeated bytes.
pub fn repeat(byte: u8) -> Repeat {
    Repeat::new(byte)
}

/// A writer that discards all bytes.
pub fn sink() -> Sink {
    Sink
}

/// A `poll(2)` descriptor from the native ABI.
pub use libpagh::abi::PollFd;

/// Poll descriptors for readiness.
///
/// `timeout` is a blocking timeout; `None` waits forever. Returns the number of
/// ready descriptors (0 on timeout). The kernel's poll is non-blocking per
/// descriptor and yields in the syscall for the timeout.
pub fn poll(fds: &mut [PollFd], timeout: Option<crate::time::Duration>) -> Result<usize> {
    let millis = match timeout {
        Some(d) => {
            let ms = d.as_millis();
            if ms > i32::MAX as u128 {
                i32::MAX
            } else {
                ms as i32
            }
        }
        None => -1,
    };
    libpagh::sys::poll(fds, millis).map_err(|e| Error::from(e))
}
