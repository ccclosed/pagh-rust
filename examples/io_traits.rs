//! `io_traits` — `Read`/`Write`/`BufRead` on `fs::File` and `net::TcpStream`.
//!
//! The default run exercises a real file: `Write::write_all`, `flush`,
//! `Seek`, `Read::read_exact`/`read_to_end`, and `BufRead` directly on a
//! `File` (`fill_buf`/`consume`/`read_line`). It also checks the read-ahead
//! contract: after `fill_buf` read ahead, a write rewinds to the logical
//! position and a later read sees exactly that byte sequence.
//!
//! With `net <ipv4> <port>` it additionally connects to a host echo server,
//! writes a request, and reads a status line through `BufRead` followed by the
//! remainder through `Read::read_to_end`. That mode needs QEMU user networking
//! (`tools/run.py --net`); without a NIC the program reports the connect error
//! instead of pretending the trait was tested.

#![no_std]
#![no_main]

use pagh_std::fs::{File, OpenOptions};
use pagh_std::net::{Ipv4, TcpStream};
use pagh_std::prelude::*;

const FILE_PATH: &str = "/mnt/io_traits.txt";

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn file_traits() -> io::Result<()> {
    // Write through `Write`, then read through `Read` and `BufRead`.
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(FILE_PATH)?;
    file.write_all(b"alpha\nbeta\ngamma\n")?;
    file.flush()?;
    if file.metadata()?.len() != 17 {
        return Err(invalid("Write::write_all wrote the wrong number of bytes"));
    }

    file.seek(SeekFrom::Start(0))?;
    let mut alpha = [0u8; 5];
    file.read_exact(&mut alpha)?;
    if &alpha != b"alpha" {
        return Err(invalid("Read::read_exact did not see 'alpha'"));
    }

    // `BufRead` directly on File, no BufReader: first line, then one byte via
    // fill_buf/consume, then the rest through Read (which must drain the
    // read-ahead buffer before another syscall).
    file.seek(SeekFrom::Start(0))?;
    let mut line = String::new();
    let line_len = file.read_line(&mut line)?;
    if line_len != 6 || line != "alpha\n" {
        return Err(invalid(
            "BufRead::read_line on File returned the wrong line",
        ));
    }
    {
        let available = file.fill_buf()?;
        if available.len() < 5 || !available.starts_with(b"beta\n") {
            return Err(invalid("BufRead::fill_buf on File did not see 'beta'"));
        }
    }
    file.consume(1); // 'b'
    let mut next = [0u8; 1];
    file.read_exact(&mut next)?;
    if next[0] != b'e' {
        return Err(invalid(
            "Read after BufRead::consume lost the logical position",
        ));
    }
    let mut rest = Vec::new();
    file.read_to_end(&mut rest)?;
    if rest != b"ta\ngamma\n" {
        return Err(invalid(
            "Read::read_to_end after read-ahead returned the wrong bytes",
        ));
    }

    // Read-ahead followed by Write: the write must land at the logical position
    // (2), not where the descriptor read-ahead left the kernel offset (6).
    file.seek(SeekFrom::Start(0))?;
    file.set_len(0)?;
    file.write_all(b"abcdef")?;
    file.seek(SeekFrom::Start(0))?;
    {
        let available = file.fill_buf()?;
        if available != b"abcdef" {
            return Err(invalid("fill_buf did not see the six written bytes"));
        }
    }
    file.consume(2);
    file.write_all(b"XY")?;
    file.seek(SeekFrom::Start(0))?;
    let mut rewritten = Vec::new();
    file.read_to_end(&mut rewritten)?;
    if rewritten != b"abXYef" {
        return Err(invalid("Write after BufRead read-ahead did not rewind"));
    }

    // BufReader still works on the same File type.
    let mut reader = BufReader::with_capacity(4, File::open(FILE_PATH)?);
    let mut first_line = String::new();
    if reader.read_line(&mut first_line)? == 0 || first_line != "abXYef" {
        return Err(invalid("BufReader<File> did not read the rewritten file"));
    }

    println!("io_traits: File Write/Read/Seek/BufRead ok ({FILE_PATH})");
    Ok(())
}

fn net_traits(host: &str, port: u16) -> io::Result<()> {
    let address = Ipv4::parse(host)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "not an IPv4 literal"))?;
    let mut stream = TcpStream::connect(address, port)?;

    stream.write_all(b"PING\n")?;
    stream.flush()?;

    // BufRead first: this fills the 8 KiB read-ahead buffer with everything the
    // server sent and consumes only the first line.
    let mut status = String::new();
    let read = stream.read_line(&mut status)?;
    if read == 0 || status != "PAGH-IO-TRAITS\n" {
        return Err(invalid(
            "TcpStream::read_line returned the wrong status line",
        ));
    }
    // Then Read: drains the rest of the same read-ahead buffer and reaches EOF.
    let mut body = Vec::new();
    let body_len = <TcpStream as Read>::read_to_end(&mut stream, &mut body)?;
    if body_len != 12 || body != b"second line\n" {
        return Err(invalid("TcpStream::read_to_end returned the wrong body"));
    }

    println!("io_traits: TcpStream Write/BufRead/Read ok ({host}:{port})");
    Ok(())
}

#[no_mangle]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let args: Vec<String> = env::args().collect();
    let mut failures = 0u32;

    match file_traits() {
        Ok(()) => {}
        Err(error) => {
            eprintln!("io_traits: File: {error}");
            failures += 1;
        }
    }

    match args.get(1).map(String::as_str) {
        None => {}
        Some("net") => {
            if args.len() != 4 {
                eprintln!("usage: io_traits [net <ipv4> <port>]");
                return 2;
            }
            match args[3].parse::<u16>() {
                Ok(port) => match net_traits(&args[2], port) {
                    Ok(()) => {}
                    Err(error) => {
                        eprintln!("io_traits: TcpStream: {error}");
                        failures += 1;
                    }
                },
                Err(_) => {
                    eprintln!("io_traits: invalid port '{}'", args[3]);
                    return 2;
                }
            }
        }
        Some(other) => {
            eprintln!("io_traits: unknown argument '{other}'");
            eprintln!("usage: io_traits [net <ipv4> <port>]");
            return 2;
        }
    }

    if failures == 0 {
        println!("IO_TRAITS PASS");
        0
    } else {
        println!("IO_TRAITS FAIL: {failures} check(s) failed");
        1
    }
}
