//! The kernel-independent half of [`super`](crate::io): the traits, the
//! adapters and the free functions that need nothing but `core` + `alloc`.
//!
//! This file is separate from `io.rs` for one reason: the host gate
//! (`hostcheck`) compiles the pure sources directly, and `io.rs` — which owns
//! the console handles and `poll` — needs `libpagh`'s RISC-V syscall layer,
//! which cannot be built for the host. Everything here is compiled twice: once
//! as `pagh_std::io` on the target and once by `cargo test -p pagh_hostcheck`.
//! Keep it free of `crate::` references other than the two re-exports below
//! (`error` and the root `Errno`), or the second build stops resolving.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use crate::error::{Error, ErrorKind, Result};
use crate::io::SeekFrom;
use crate::Errno;

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

    /// Read this reader to end of file, then continue with `next`.
    ///
    /// The concatenation is lazy: `next` is untouched until `self` reports
    /// EOF, so a reader that never ends keeps `next` unread forever. When both
    /// readers are [`BufRead`], the returned [`Chain`] is too — and unlike a
    /// `BufReader`-wrapped pair it does not re-buffer what is already buffered.
    fn chain<R: Read>(self, next: R) -> Chain<Self, R>
    where
        Self: Sized,
    {
        Chain {
            first: self,
            second: next,
            done_first: false,
        }
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
// Chain
// ---------------------------------------------------------------------------

/// Reader returned by [`Read::chain`]: it reads `first` to end of file and then
/// continues with `second`.
///
/// [`BufRead`] is implemented whenever both readers are buffered. As in std,
/// the adapter does not wrap either reader in a buffer: it hands out the slice
/// the current reader already has, which is also why `Chain<Cursor<..>, ..>` is
/// cheap.
#[derive(Debug)]
pub struct Chain<T, U> {
    first: T,
    second: U,
    done_first: bool,
}

impl<T, U> Chain<T, U> {
    /// The wrapped readers, in reading order.
    pub fn get_ref(&self) -> (&T, &U) {
        (&self.first, &self.second)
    }

    /// The wrapped readers mutably. Reading from `first` through this reference
    /// cannot clear the adapter's "first is finished" state; use
    /// [`Chain::into_inner`] when handing the readers over.
    pub fn get_mut(&mut self) -> (&mut T, &mut U) {
        (&mut self.first, &mut self.second)
    }

    /// Give both readers back.
    pub fn into_inner(self) -> (T, U) {
        (self.first, self.second)
    }
}

impl<T: Read, U: Read> Read for Chain<T, U> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if !self.done_first {
            match self.first.read(buf)? {
                // A zero-length read cannot mean EOF: `read(&mut [])` must not
                // advance the chain to its second reader, exactly like std.
                0 if !buf.is_empty() => self.done_first = true,
                n => return Ok(n),
            }
        }
        self.second.read(buf)
    }
}

impl<T: BufRead, U: BufRead> BufRead for Chain<T, U> {
    fn fill_buf(&mut self) -> Result<&[u8]> {
        if !self.done_first {
            match self.first.fill_buf()? {
                [] => self.done_first = true,
                available => return Ok(available),
            }
        }
        self.second.fill_buf()
    }

    fn consume(&mut self, amt: usize) {
        if !self.done_first {
            self.first.consume(amt);
        } else {
            self.second.consume(amt);
        }
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
// Cursor
// ---------------------------------------------------------------------------

/// A [`Read`]/[`BufRead`]/[`Seek`] adapter over an in-memory byte slice.
///
/// This is `std::io::Cursor` for the SDK's traits: `new`, `into_inner`,
/// `get_ref`, `get_mut`, `position` and `set_position` keep std's names and
/// semantics. `SeekFrom::Start` and `SeekFrom::End` behave like std's — seeking
/// past the end is allowed and the next `read` reports EOF — and a seek that
/// would land on a negative or overflowing position is
/// [`ErrorKind::InvalidInput`], not a panic.
///
/// # Reader and writer cursors
///
/// The generic `Cursor<T>` is a reader (`Read`, `BufRead`, `Seek`). As in std,
/// `Write` is implemented separately for the concrete in-memory writers:
/// `Cursor<Vec<u8>>` and `Cursor<&mut Vec<u8>>` grow and zero-pad when the
/// position is past the end, while `Cursor<&mut [u8]>`, `Cursor<[u8; N]>` and
/// `Cursor<Box<[u8]>>` write into the fixed buffer and report a short write at
/// its end (with `write_all` reporting [`ErrorKind::WriteZero`]). Writing needs
/// either a growable vector or a fixed slice, which is exactly why std spells
/// out the same separate impls. `consume` saturates instead of letting the
/// position wrap, which is the same observable behaviour for every caller that
/// respects the trait contract.
#[derive(Clone, Debug, Default)]
pub struct Cursor<T> {
    inner: T,
    pos: u64,
}

impl<T> Cursor<T> {
    /// Wrap `inner` with the position at the start.
    pub const fn new(inner: T) -> Cursor<T> {
        Cursor { inner, pos: 0 }
    }

    /// The current position in bytes.
    pub const fn position(&self) -> u64 {
        self.pos
    }

    /// Set the position; the next read starts there and a read past the end
    /// reports EOF.
    pub fn set_position(&mut self, position: u64) {
        self.pos = position;
    }

    /// A shared reference to the wrapped buffer.
    pub const fn get_ref(&self) -> &T {
        &self.inner
    }

    /// A mutable reference to the wrapped buffer. Mutating it behind a live
    /// position can move the end of file; prefer [`Cursor::into_inner`].
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Give the wrapped buffer back, discarding the position.
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: AsRef<[u8]>> Read for Cursor<T> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let data = self.inner.as_ref();
        // A position past the end is legal (std allows it after a seek): the
        // window then starts at the end and the read is an EOF.
        let pos = core::cmp::min(self.pos, data.len() as u64) as usize;
        let n = core::cmp::min(buf.len(), data.len() - pos);
        buf[..n].copy_from_slice(&data[pos..pos + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl<T: AsRef<[u8]>> BufRead for Cursor<T> {
    fn fill_buf(&mut self) -> Result<&[u8]> {
        let data = self.inner.as_ref();
        let pos = core::cmp::min(self.pos, data.len() as u64) as usize;
        Ok(&data[pos..])
    }

    fn consume(&mut self, amt: usize) {
        self.pos = self.pos.saturating_add(amt as u64);
    }
}

impl<T: AsRef<[u8]>> Seek for Cursor<T> {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
        let (base, offset) = match pos {
            // std keeps a position past the end instead of clamping it; the
            // next read is an EOF and `position()` reports the value.
            SeekFrom::Start(n) => {
                self.pos = n;
                return Ok(n);
            }
            SeekFrom::Current(delta) => (self.pos as i128, delta as i128),
            SeekFrom::End(delta) => (self.inner.as_ref().len() as i128, delta as i128),
        };
        let new_pos = base + offset;
        if !(0..=usize::MAX as i128).contains(&new_pos) {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "invalid seek to a negative or overflowing position",
            ));
        }
        self.pos = new_pos as u64;
        Ok(self.pos)
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
// Tee
// ---------------------------------------------------------------------------

/// A [`Write`] adapter that mirrors everything it accepts into two sinks, the
/// wrapped writer and a second writer (std calls the second one `file`).
///
/// `std::io::Tee` is nightly-only (`#![feature(io_tee)]`); this is the same
/// type on the SDK's stable surface. Every byte `writer` accepts is written to
/// `file` with `write_all`, so the two receive the same stream; if `file` fails,
/// that error is returned even though `writer` already took the bytes — the
/// same trade std makes, and why the adapter is for logging rather than for
/// transactional duplication.
#[derive(Debug)]
pub struct Tee<W, F> {
    writer: W,
    file: F,
}

impl<W: Write, F: Write> Tee<W, F> {
    /// Write to `writer` and mirror the accepted bytes into `file`.
    pub fn new(writer: W, file: F) -> Tee<W, F> {
        Tee { writer, file }
    }
}

impl<W, F> Tee<W, F> {
    /// The wrapped writer and file, in that order.
    pub fn get_ref(&self) -> (&W, &F) {
        (&self.writer, &self.file)
    }

    /// The wrapped writer and file mutably.
    pub fn get_mut(&mut self) -> (&mut W, &mut F) {
        (&mut self.writer, &mut self.file)
    }

    /// Give both writers back.
    pub fn into_inner(self) -> (W, F) {
        (self.writer, self.file)
    }
}

impl<W: Write, F: Write> Write for Tee<W, F> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let n = self.writer.write(buf)?;
        if n > buf.len() {
            // A writer that lies about the count would panic a slice index;
            // report it as data corruption instead.
            return Err(Error::new(
                ErrorKind::InvalidData,
                "writer claimed to write more bytes than it was given",
            ));
        }
        self.file.write_all(&buf[..n])?;
        Ok(n)
    }

    fn flush(&mut self) -> Result<()> {
        self.writer.flush()?;
        self.file.flush()
    }
}

// ---------------------------------------------------------------------------
// In-memory writers and readers
// ---------------------------------------------------------------------------

/// Writes into a `Vec<u8>` by appending, growing it as needed.
///
/// This is std's in-memory sink and its `write!` destination. Every byte is
/// accepted — `write` never reports a short write — and an allocation failure
/// is a typed [`ErrorKind::OutOfMemory`] instead of an abort, because the SDK
/// maps `try_reserve` failures that way everywhere it can.
impl Write for Vec<u8> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.try_reserve(buf.len())
            .map_err(|_| Error::from(Errno::ENOMEM))?;
        self.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        self.write(buf).map(|_| ())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Writes into a `&mut [u8]` by copying and then advancing the slice.
///
/// std's shape: the slice is updated to point at the not-yet-written part, so
/// it is empty when full and `write` then returns `Ok(0)`; a write that does
/// not fit is short, and `write_all` reports [`ErrorKind::WriteZero`] when the
/// destination runs out.
impl Write for &mut [u8] {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let n = core::cmp::min(buf.len(), self.len());
        let (head, tail) = core::mem::take(self).split_at_mut(n);
        head.copy_from_slice(&buf[..n]);
        *self = tail;
        Ok(n)
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        if self.write(buf)? < buf.len() {
            return Err(Error::new(
                ErrorKind::WriteZero,
                "failed to write whole buffer",
            ));
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Reads from the remaining part of a `&[u8]`.
///
/// std's shape: `fill_buf` returns the unread bytes, `consume` advances the
/// slice, so `read_until`/`read_line`/`lines` work over a borrowed buffer
/// without copying. `consume` is clamped to the available bytes (this SDK's
/// trait contract) instead of panicking on an over-long count.
impl BufRead for &[u8] {
    fn fill_buf(&mut self) -> Result<&[u8]> {
        Ok(*self)
    }

    fn consume(&mut self, amt: usize) {
        let n = core::cmp::min(amt, self.len());
        *self = &self[n..];
    }
}

/// Non-resizing cursor write: copy into `slice` at `pos`, clamped to its end.
fn cursor_slice_write(pos: &mut u64, slice: &mut [u8], buf: &[u8]) -> usize {
    let start = core::cmp::min(*pos, slice.len() as u64) as usize;
    let n = core::cmp::min(buf.len(), slice.len() - start);
    slice[start..start + n].copy_from_slice(&buf[..n]);
    *pos += n as u64;
    n
}

/// Resizing cursor write: grow and zero-pad the vector when `pos` is past its
/// end, then write every byte (this cursor never reports a short write).
fn cursor_vec_write(pos: &mut u64, vec: &mut Vec<u8>, buf: &[u8]) -> Result<()> {
    let position = usize::try_from(*pos).map_err(|_| {
        Error::new(
            ErrorKind::InvalidInput,
            "cursor position exceeds the addressable length",
        )
    })?;
    let end = position
        .checked_add(buf.len())
        .ok_or_else(|| Error::from(Errno::ENOMEM))?;
    if end > vec.len() {
        vec.try_reserve(end - vec.len())
            .map_err(|_| Error::from(Errno::ENOMEM))?;
    }
    if position > vec.len() {
        // std pads the gap with zero bytes; this is the one place a cursor
        // invents data, and it is the documented behaviour.
        vec.resize(position, 0);
    }
    let writable = core::cmp::min(buf.len(), vec.len() - position);
    if writable > 0 {
        vec[position..position + writable].copy_from_slice(&buf[..writable]);
    }
    if writable < buf.len() {
        // Capacity was reserved above, so this cannot allocate.
        vec.extend_from_slice(&buf[writable..]);
    }
    *pos += buf.len() as u64;
    Ok(())
}

impl Write for Cursor<Vec<u8>> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        cursor_vec_write(&mut self.pos, &mut self.inner, buf)?;
        Ok(buf.len())
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        self.write(buf).map(|_| ())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

impl Write for Cursor<&mut Vec<u8>> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        cursor_vec_write(&mut self.pos, &mut *self.inner, buf)?;
        Ok(buf.len())
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        self.write(buf).map(|_| ())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

impl Write for Cursor<&mut [u8]> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        Ok(cursor_slice_write(&mut self.pos, &mut *self.inner, buf))
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        if self.write(buf)? < buf.len() {
            return Err(Error::new(
                ErrorKind::WriteZero,
                "failed to write whole buffer",
            ));
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

impl<const N: usize> Write for Cursor<[u8; N]> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        Ok(cursor_slice_write(&mut self.pos, &mut self.inner[..], buf))
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        if self.write(buf)? < buf.len() {
            return Err(Error::new(
                ErrorKind::WriteZero,
                "failed to write whole buffer",
            ));
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

impl Write for Cursor<Box<[u8]>> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        Ok(cursor_slice_write(&mut self.pos, &mut self.inner[..], buf))
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        if self.write(buf)? < buf.len() {
            return Err(Error::new(
                ErrorKind::WriteZero,
                "failed to write whole buffer",
            ));
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
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
