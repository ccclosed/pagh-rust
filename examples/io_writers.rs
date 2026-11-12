//! `io_writers` — the 0.11.0 in-memory writers and readers.
//!
//! The SDK's `io::Write`/`io::BufRead` traits now have std's in-memory
//! implementations, so a program can build or consume a byte buffer without a
//! file. Seven sections, each returning a message describing the violated
//! invariant instead of printing "ok" blindly:
//!
//! 1. `Vec<u8>` as a sink: `write_all`, and `write!`/`writeln!` formatting
//!    through `Write::write_fmt`;
//! 2. `&mut [u8]` as a fixed sink: short writes, the slice advancing, and
//!    `write_all` failing with `WriteZero` at the end;
//! 3. `Cursor<Vec<u8>>`: writing at a position, overwriting in place, padding
//!    with zero bytes past the end, then reading the same cursor back;
//! 4. the bounded writer cursors (`Cursor<&mut [u8]>`, `Cursor<[u8; N]>`,
//!    `Cursor<Box<[u8]>>`) and their `WriteZero` at the end;
//! 5. `BufRead for &[u8]`: `fill_buf`/`consume`/`read_until`/`lines` over a
//!    borrowed buffer;
//! 6. `fmt::Write` and the `str`/`String` helpers: both came from `core`/
//!    `alloc` (the triage conclusion for 0.11.0), demonstrated on the target;
//! 7. composition: `copy` into a `Vec`, `Tee` over two in-memory sinks, and a
//!    `BufWriter<Vec<u8>>` flush.
//!
//! The program prints one line per area and `IO_WRITERS PASS`, or the failed
//! invariant and exit code 1 (`tools/live_110.py` checks both).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use pagh_std::fmt::Write as _;
use pagh_std::prelude::*;

fn vec_sink() -> Result<(), &'static str> {
    let mut sink = Vec::new();
    if sink.write(b"ab").unwrap_or(0) != 2 {
        return Err("Write for Vec<u8> did not accept two bytes");
    }
    sink.write_all(b"cd")
        .map_err(|_| "write_all into Vec failed")?;
    write!(sink, " value={}", 42).map_err(|_| "write! into Vec failed")?;
    writeln!(sink).map_err(|_| "writeln! into Vec failed")?;
    if sink != b"abcd value=42\n" {
        return Err("the Vec<u8> sink holds the wrong bytes");
    }
    if sink.flush().is_err() {
        return Err("flushing a Vec<u8> sink failed");
    }
    println!(
        "io_writers: Vec<u8> sink ok ({} bytes, write!/writeln! via write_fmt)",
        sink.len()
    );
    Ok(())
}

fn slice_sink() -> Result<(), &'static str> {
    let mut storage = [0u8; 5];
    {
        let mut sink: &mut [u8] = &mut storage;
        if sink.write(b"abc") != Ok(3) || sink.len() != 2 {
            return Err("&mut [u8] write did not consume three bytes");
        }
        // Only two bytes remain, so this has to be a short write.
        if sink.write(b"def") != Ok(2) || !sink.is_empty() {
            return Err("&mut [u8] write did not stop at the end of the slice");
        }
        // A full destination accepts nothing.
        if sink.write(b"z") != Ok(0) {
            return Err("a full &mut [u8] accepted a byte");
        }
    }
    if &storage != b"abcde" {
        return Err("&mut [u8] wrote different bytes than it reported");
    }

    let mut small = [0u8; 3];
    let error = {
        let mut sink: &mut [u8] = &mut small;
        sink.write_all(b"abcd").err()
    };
    match error {
        Some(error) if error.kind() == io::ErrorKind::WriteZero => {}
        _ => return Err("write_all into a too-small &mut [u8] did not report WriteZero"),
    }
    if &small != b"abc" {
        return Err("write_all into &mut [u8] lost the bytes that fit");
    }
    println!("io_writers: &mut [u8] sink ok (short write, advancing slice, WriteZero)");
    Ok(())
}

fn cursor_vec_writer() -> Result<(), &'static str> {
    let mut cursor = Cursor::new(Vec::new());
    cursor
        .write_all(b"abc")
        .map_err(|_| "Cursor<Vec> write_all failed")?;
    if cursor.position() != 3 || cursor.get_ref().as_slice() != b"abc" {
        return Err("Cursor<Vec> position/length disagree after writing");
    }

    // Seeking back overwrites in place.
    cursor
        .seek(SeekFrom::Start(1))
        .map_err(|_| "Cursor<Vec> seek failed")?;
    cursor
        .write_all(b"XY")
        .map_err(|_| "Cursor<Vec> overwrite failed")?;
    if cursor.get_ref().as_slice() != b"aXY" || cursor.position() != 3 {
        return Err("Cursor<Vec> did not overwrite at the position");
    }

    // Seeking past the end and writing pads the gap with zero bytes.
    cursor
        .seek(SeekFrom::Start(6))
        .map_err(|_| "Cursor<Vec> seek past end failed")?;
    cursor
        .write_all(b"z")
        .map_err(|_| "Cursor<Vec> append after gap failed")?;
    let expected: &[u8] = &[b'a', b'X', b'Y', 0, 0, 0, b'z'];
    if cursor.get_ref().as_slice() != expected || cursor.position() != 7 {
        return Err("Cursor<Vec> did not zero-pad the gap");
    }

    // The read side of the same cursor sees the padded bytes.
    cursor.rewind().map_err(|_| "Cursor<Vec> rewind failed")?;
    let mut roundtrip = Vec::new();
    cursor
        .read_to_end(&mut roundtrip)
        .map_err(|_| "Cursor<Vec> read-back failed")?;
    if roundtrip != expected {
        return Err("Cursor<Vec> read-back differs from what was written");
    }
    println!("io_writers: Cursor<Vec<u8>> writer ok (overwrite, zero-pad, read-back, 7 bytes)");
    Ok(())
}

fn cursor_fixed_writers() -> Result<(), &'static str> {
    // Cursor<&mut [u8]>: bounded by the slice.
    let mut storage = [0u8; 4];
    {
        let mut cursor = Cursor::new(&mut storage[..]);
        if cursor.write(b"abcd") != Ok(4) {
            return Err("Cursor<&mut [u8]> failed to fill the slice");
        }
        if cursor.write(b"e") != Ok(0) {
            return Err("Cursor<&mut [u8]> wrote past the end of the slice");
        }
        cursor
            .seek(SeekFrom::Start(0))
            .map_err(|_| "Cursor<&mut [u8]> seek failed")?;
        if cursor.write(b"XY") != Ok(2) {
            return Err("Cursor<&mut [u8]> failed to overwrite");
        }
        cursor
            .seek(SeekFrom::Start(3))
            .map_err(|_| "Cursor<&mut [u8]> seek failed")?;
        match cursor.write_all(b"xyz") {
            Err(error) if error.kind() == io::ErrorKind::WriteZero => {}
            _ => return Err("Cursor<&mut [u8]> did not report WriteZero"),
        }
    }
    if &storage != b"XYcx" {
        return Err("Cursor<&mut [u8]> wrote different bytes than it reported");
    }

    // Cursor<[u8; N]> owns the array; Cursor<Box<[u8]>> owns a boxed slice.
    let mut array = Cursor::new([0u8; 3]);
    array
        .write_all(b"ab")
        .map_err(|_| "Cursor<[u8; N]> write failed")?;
    if array.get_ref() != &[b'a', b'b', 0] {
        return Err("Cursor<[u8; N]> wrote the wrong bytes");
    }
    let mut boxed = Cursor::new(alloc::vec![0u8; 4].into_boxed_slice());
    boxed
        .seek(SeekFrom::Start(1))
        .map_err(|_| "Cursor<Box<[u8]>> seek failed")?;
    boxed
        .write_all(b"xy")
        .map_err(|_| "Cursor<Box<[u8]>> write failed")?;
    if boxed.get_ref().as_ref() != &[0, b'x', b'y', 0] || boxed.position() != 3 {
        return Err("Cursor<Box<[u8]>> wrote the wrong bytes");
    }
    println!("io_writers: bounded writer cursors ok (&mut [u8], [u8; N], Box<[u8]>)");
    Ok(())
}

fn bufread_slice() -> Result<(), &'static str> {
    let data = b"line one\nline two\n";
    let mut reader: &[u8] = data;
    if reader.fill_buf() != Ok(data) {
        return Err("BufRead for &[u8] did not hand out the whole slice");
    }
    reader.consume(5);
    let mut line = Vec::new();
    if reader.read_until(b'\n', &mut line) != Ok(4) || line != b"one\n" {
        return Err("read_until over &[u8] returned the wrong bytes");
    }

    let lines_reader: &[u8] = data;
    let mut lines = 0u32;
    for line in lines_reader.lines() {
        match line {
            Ok(text) if !text.is_empty() => lines += 1,
            Ok(_) => return Err("lines() over &[u8] yielded an empty line"),
            Err(_) => return Err("lines() over &[u8] failed to decode"),
        }
    }
    if lines != 2 {
        return Err("lines() over &[u8] did not find two lines");
    }

    let mut exhausted: &[u8] = b"abc";
    exhausted.consume(100);
    if !exhausted.is_empty() || exhausted.read(&mut [0u8; 1]) != Ok(0) {
        return Err("consume past the end of &[u8] did not clamp");
    }
    println!("io_writers: BufRead for &[u8] ok (fill_buf/consume/read_until/lines)");
    Ok(())
}

fn fmt_write_and_str_helpers() -> Result<(), &'static str> {
    // `pagh_std::fmt::Write` is `core::fmt::Write`, and `String` implements it
    // through `alloc`: no SDK code is needed for the formatting sink.
    let mut text = String::new();
    write!(text, "{:>5}", "ab").map_err(|_| "write! into String failed")?;
    write!(text, "|{}", 7).map_err(|_| "write! into String failed")?;
    if text != "   ab|7" {
        return Err("formatting into a String produced the wrong text");
    }

    // The `str`/`String` helpers are core/alloc too, not something the SDK can
    // be missing: trim, case conversion, replace, split_whitespace.
    let source = "  hello writers  ";
    let trimmed = source.trim();
    if trimmed != "hello writers" {
        return Err("str::trim returned the wrong text");
    }
    if trimmed.to_uppercase() != "HELLO WRITERS" {
        return Err("str::to_uppercase returned the wrong text");
    }
    if trimmed.replace("writers", "world") != "hello world" {
        return Err("str::replace returned the wrong text");
    }
    if trimmed.split_whitespace().count() != 2 || !trimmed.starts_with("hello") {
        return Err("str::split_whitespace/starts_with disagree");
    }
    let formatted = format!("{} + {} = {}", 1, 2, 3);
    if formatted != "1 + 2 = 3" {
        return Err("format! returned the wrong text");
    }
    println!("io_writers: fmt::Write + String/str helpers ok (trim/uppercase/replace/split)");
    Ok(())
}

fn composition() -> Result<(), &'static str> {
    // `copy` from a borrowed slice reader into the Vec sink.
    let mut source: &[u8] = b"compose";
    let mut sink = Vec::new();
    if io::copy(&mut source, &mut sink) != Ok(7) || sink != b"compose" || !source.is_empty() {
        return Err("copy(&[u8] -> Vec<u8>) returned the wrong result");
    }

    // Tee mirrors into two in-memory sinks: no file, no kernel object.
    let mut tee = Tee::new(Vec::new(), Vec::new());
    tee.write_all(b"mirror")
        .map_err(|_| "Tee into two Vecs failed")?;
    tee.flush().map_err(|_| "Tee flush failed")?;
    let (writer, file) = tee.into_inner();
    if writer != b"mirror" || file != b"mirror" {
        return Err("Tee did not mirror into both Vec sinks");
    }

    // BufWriter batches into a Vec and flushes the bytes in order.
    let mut buffered = BufWriter::with_capacity(16, Vec::new());
    buffered
        .write_all(b"batched")
        .map_err(|_| "BufWriter<Vec> write failed")?;
    if buffered.buffer() != b"batched" {
        return Err("BufWriter<Vec> did not buffer the write");
    }
    buffered
        .flush()
        .map_err(|_| "BufWriter<Vec> flush failed")?;
    let bytes = buffered
        .into_inner()
        .map_err(|_| "BufWriter<Vec> into_inner failed")?;
    if bytes != b"batched" {
        return Err("BufWriter<Vec> flushed different bytes");
    }
    println!("io_writers: composition ok (copy, Tee over two Vecs, BufWriter<Vec>)");
    Ok(())
}

#[no_mangle]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let mut failures = 0u32;
    for (name, result) in [
        ("Vec<u8> sink", vec_sink()),
        ("&mut [u8] sink", slice_sink()),
        ("Cursor<Vec<u8>> writer", cursor_vec_writer()),
        ("bounded writer cursors", cursor_fixed_writers()),
        ("BufRead for &[u8]", bufread_slice()),
        ("fmt::Write + str helpers", fmt_write_and_str_helpers()),
        ("composition", composition()),
    ] {
        if let Err(message) = result {
            eprintln!("io_writers: {name}: {message}");
            failures += 1;
        }
    }
    if failures == 0 {
        println!("IO_WRITERS PASS");
        0
    } else {
        println!("IO_WRITERS FAIL: {failures} check(s) failed");
        1
    }
}
