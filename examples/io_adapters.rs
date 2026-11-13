//! `io_adapters` — the userland I/O conveniences added in 0.9.0.
//!
//! Three sections, each a self-contained check that returns a typed [`io::Error`]
//! instead of printing a "looks fine" line:
//!
//! 1. [`io::Cursor`] over an in-memory byte buffer: reads across buffer
//!    boundaries, `position`/`set_position`, `Seek` with `Start`/`Current`/`End`
//!    (including a position past the end and the rejected negative seek), and
//!    `BufRead` (`fill_buf`/`consume`/`read_until`);
//! 2. [`Read::chain`] over readers of different kinds — two cursors, an empty
//!    reader, and a real `File` — plus `BufRead` on a chain (the hand-off from
//!    the first reader's window to the second);
//! 3. [`Tee`] mirroring a writer into a second sink: it writes one line to
//!    `stdout` *and* to a file, flushes, then reads the file back through a
//!    [`Cursor`] and compares it byte for byte.
//!
//! The program prints one line per area and `IO_ADAPTERS PASS`; a failure prints
//! the violating invariant and exits 1, which is what the live matrix
//! (`tools/live_090.py`) checks. It needs no arguments and no network.

#![no_std]
#![no_main]

use pagh_std::fs::{File, OpenOptions};
use pagh_std::prelude::*;

const TEE_PATH: &str = "/mnt/io_adapters_tee.txt";
const TEE_LINE: &[u8] = b"tee: this line goes to stdout and to the file\n";

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn cursor_checks() -> io::Result<()> {
    let mut cursor = Cursor::new(b"abcdefghij".to_vec());
    if cursor.position() != 0 {
        return Err(invalid("Cursor::new did not start at position 0"));
    }

    // Three reads across a 10-byte buffer: short, shorter, rest.
    let mut first = [0u8; 3];
    cursor.read_exact(&mut first)?;
    if &first != b"abc" || cursor.position() != 3 {
        return Err(invalid(
            "Cursor::read/position disagree at the first boundary",
        ));
    }
    let mut second = [0u8; 4];
    cursor.read_exact(&mut second)?;
    if &second != b"defg" || cursor.position() != 7 {
        return Err(invalid("Cursor::read/position disagree mid-buffer"));
    }
    let mut rest = Vec::new();
    if cursor.read_to_end(&mut rest)? != 3 || rest != b"hij" {
        return Err(invalid("Cursor::read_to_end returned the wrong tail"));
    }
    if cursor.position() != 10 || cursor.read(&mut second)? != 0 {
        return Err(invalid("Cursor did not report EOF at the end"));
    }

    // Seek: Start, Current, End, then past the end and back.
    if cursor.seek(SeekFrom::Start(4))? != 4 {
        return Err(invalid("Cursor::seek(Start) returned the wrong position"));
    }
    if cursor.seek(SeekFrom::Current(-2))? != 2 {
        return Err(invalid("Cursor::seek(Current) returned the wrong position"));
    }
    if cursor.seek(SeekFrom::End(-3))? != 7 {
        return Err(invalid("Cursor::seek(End) returned the wrong position"));
    }
    cursor.set_position(3);
    let mut byte = [0u8; 1];
    cursor.read_exact(&mut byte)?;
    if byte != [b'd'] {
        return Err(invalid("Cursor::set_position did not land on the byte"));
    }
    if cursor.seek(SeekFrom::Start(64))? != 64 || cursor.read(&mut byte)? != 0 {
        return Err(invalid("Cursor did not allow a position past the end"));
    }
    // A relative seek that would land *before* byte 0 is the rejected case; the
    // same offset from position 64 is a legal move backwards.
    cursor.seek(SeekFrom::Start(0))?;
    match cursor.seek(SeekFrom::Current(-1)) {
        Err(error) if error.kind() == io::ErrorKind::InvalidInput => {}
        _ => return Err(invalid("Cursor accepted a seek to a negative position")),
    }
    if cursor.position() != 0 {
        return Err(invalid("a rejected seek moved the Cursor position"));
    }

    // BufRead: fill/consume/read_until over the same cursor type.
    let mut cursor = Cursor::new(b"line one\nline two\n".to_vec());
    if cursor.fill_buf()? != b"line one\nline two\n" {
        return Err(invalid("Cursor::fill_buf did not expose the whole window"));
    }
    // Five bytes of "line one\n" are consumed, so the first line left is the
    // four-byte tail "one\n".
    cursor.consume(5);
    let mut line = Vec::new();
    if cursor.read_until(b'\n', &mut line)? != 4 || line != b"one\n" {
        return Err(invalid("Cursor::read_until consumed the wrong bytes"));
    }
    let mut second_line = String::new();
    if cursor.read_line(&mut second_line)? != 9 || second_line != "line two\n" {
        return Err(invalid("Cursor::read_line decoded the wrong line"));
    }
    if cursor.fill_buf()?.is_empty() != true {
        return Err(invalid("Cursor::fill_buf did not report EOF"));
    }

    println!("io_adapters: Cursor read/seek/position/BufRead ok (10-byte buffer)");
    Ok(())
}

fn chain_checks() -> io::Result<()> {
    // Two in-memory readers, then a real file and a borrowed tail: the chain is
    // generic over `Read`, so all four combinations have to be one code path.
    let mut chain = Cursor::new(b"abc".to_vec()).chain(Cursor::new(b"de".to_vec()));
    let mut out = Vec::new();
    if chain.read_to_end(&mut out)? != 5 || out != b"abcde" {
        return Err(invalid("Chain did not concatenate two cursors"));
    }

    // Empty first reader: the chain starts on the second one directly.
    let mut empty_first = Cursor::new(Vec::<u8>::new()).chain(Cursor::new(b"xyz"));
    let mut out = Vec::new();
    if empty_first.read_to_end(&mut out)? != 3 || out != b"xyz" {
        return Err(invalid("Chain did not skip an empty first reader"));
    }

    // Empty second reader: the first reader's bytes are all there is, and the
    // chain then reports EOF instead of inventing bytes.
    let mut empty_second = Cursor::new(b"abc".to_vec()).chain(Cursor::new(&b""[..]));
    let mut out = Vec::new();
    if empty_second.read_to_end(&mut out)? != 3 || out != b"abc" {
        return Err(invalid("Chain appended bytes from an empty second reader"));
    }
    let mut byte = [0u8; 1];
    if empty_second.read(&mut byte)? != 0 {
        return Err(invalid(
            "Chain did not report EOF after the empty second reader",
        ));
    }

    // Both readers empty.
    let mut both_empty = Cursor::new(&b""[..]).chain(Cursor::new(&b""[..]));
    if both_empty.read_to_end(&mut out)? != 0 || out != b"abc" {
        return Err(invalid("an empty Chain appended bytes"));
    }

    // A real File as the first reader: write a fixture, reopen it, chain it with
    // a cursor, and require the concatenation through `read_exact`.
    let path = "/mnt/io_adapters_chain.txt";
    {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        file.write_all(b"file:")?;
        file.flush()?;
    }
    let mut chain = File::open(path)?.chain(Cursor::new(b"cursor"));
    let mut together = [0u8; 11];
    chain.read_exact(&mut together)?;
    if &together != b"file:cursor" {
        return Err(invalid("Chain<File, Cursor> read the wrong bytes"));
    }
    if chain.read(&mut together[..1])? != 0 {
        return Err(invalid("Chain<File, Cursor> did not report EOF"));
    }

    // BufRead on a chain: the window comes from the first reader, then switches.
    let mut chain = Cursor::new(b"ab".to_vec()).chain(Cursor::new(b"cd\n"));
    if chain.fill_buf()? != b"ab" {
        return Err(invalid("Chain::fill_buf did not serve the first reader"));
    }
    chain.consume(2);
    if chain.fill_buf()? != b"cd\n" {
        return Err(invalid(
            "Chain::fill_buf did not hand over to the second reader",
        ));
    }
    chain.consume(2);
    let mut tail = Vec::new();
    if chain.read_until(b'\n', &mut tail)? != 1 || tail != b"\n" {
        return Err(invalid(
            "Chain::read_until missed the delimiter in the second reader",
        ));
    }

    println!("io_adapters: Chain ok (2 cursors, 2 empty cases, File + cursor)");
    Ok(())
}

fn tee_checks() -> io::Result<()> {
    // The file has to be created first: `Tee` mirrors into a writer it is given,
    // it does not open one.
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(TEE_PATH)?;
    let mut tee = Tee::new(io::stdout(), file);
    tee.write_all(TEE_LINE)?;
    tee.flush()?;
    // `into_inner` is how a caller gets both sinks back; neither needs a close
    // here (`File` closes on drop, `Stdout` is a zero-sized handle).
    let (_stdout, _file) = tee.into_inner();

    // Read the mirrored file back through a Cursor and compare exactly.
    let mut cursor = Cursor::new(pagh_std::fs::read(TEE_PATH)?);
    let mut mirrored = Vec::new();
    cursor.read_to_end(&mut mirrored)?;
    if mirrored != TEE_LINE {
        return Err(invalid(
            "Tee's file half received different bytes than stdout",
        ));
    }
    if cursor.position() != TEE_LINE.len() as u64 {
        return Err(invalid("reading the mirrored file back lost the position"));
    }

    println!(
        "io_adapters: Tee ok ({} bytes to stdout and {TEE_PATH})",
        mirrored.len()
    );
    Ok(())
}

#[no_mangle]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let mut failures = 0u32;
    for (name, result) in [
        ("Cursor", cursor_checks()),
        ("Chain", chain_checks()),
        ("Tee", tee_checks()),
    ] {
        if let Err(error) = result {
            eprintln!("io_adapters: {name}: {error}");
            failures += 1;
        }
    }
    if failures == 0 {
        println!("IO_ADAPTERS PASS");
        0
    } else {
        println!("IO_ADAPTERS FAIL: {failures} check(s) failed");
        1
    }
}
