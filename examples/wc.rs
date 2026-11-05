//! `wc` — count lines, words and bytes.
//!
//! Exercises `BufReader`, `BufRead::read_until`, `BufWriter`, `write!` and
//! argument parsing. Counts are streamed; files are never read into memory as a
//! whole.

#![no_std]
#![no_main]

use pagh_std::fs::File;
use pagh_std::prelude::*;

#[derive(Clone, Copy, Default)]
struct Counts {
    lines: u64,
    words: u64,
    bytes: u64,
}

impl Counts {
    fn add(&mut self, other: Counts) {
        self.lines = self.lines.saturating_add(other.lines);
        self.words = self.words.saturating_add(other.words);
        self.bytes = self.bytes.saturating_add(other.bytes);
    }
}

fn count<R: BufRead>(reader: &mut R) -> io::Result<Counts> {
    let mut counts = Counts::default();
    let mut line: Vec<u8> = Vec::new();
    loop {
        line.clear();
        let n = reader.read_until(b'\n', &mut line)?;
        if n == 0 {
            return Ok(counts);
        }
        counts.bytes = counts.bytes.saturating_add(n as u64);
        if line.last() == Some(&b'\n') {
            counts.lines = counts.lines.saturating_add(1);
        }
        let words = line
            .split(|byte| byte.is_ascii_whitespace())
            .filter(|word| !word.is_empty())
            .count();
        counts.words = counts.words.saturating_add(words as u64);
    }
}

fn usage() {
    eprintln!("usage: wc [-l] [-w] [-c] [file...]");
    eprintln!("  -  read standard input (the pagh console has no EOF)");
}

fn print_counts<W: Write>(
    out: &mut W,
    counts: Counts,
    show_lines: bool,
    show_words: bool,
    show_bytes: bool,
    name: &str,
) -> io::Result<()> {
    let mut first = true;
    if show_lines {
        write!(out, "{:>7}", counts.lines)?;
        first = false;
    }
    if show_words {
        if !first {
            write!(out, " ")?;
        }
        write!(out, "{:>7}", counts.words)?;
        first = false;
    }
    if show_bytes {
        if !first {
            write!(out, " ")?;
        }
        write!(out, "{:>7}", counts.bytes)?;
    }
    if !name.is_empty() {
        write!(out, " {}", name)?;
    }
    writeln!(out)
}

#[no_mangle]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let args: Vec<String> = env::args().collect();
    let mut show_lines = false;
    let mut show_words = false;
    let mut show_bytes = false;
    let mut any_selector = false;
    let mut files: Vec<String> = Vec::new();
    let mut options_done = false;

    for arg in args.iter().skip(1) {
        if !options_done && arg == "--" {
            options_done = true;
            continue;
        }
        if !options_done && arg.starts_with('-') && arg != "-" {
            if arg == "-h" || arg == "--help" {
                usage();
                return 0;
            }
            for flag in arg[1..].chars() {
                match flag {
                    'l' => {
                        show_lines = true;
                        any_selector = true;
                    }
                    'w' => {
                        show_words = true;
                        any_selector = true;
                    }
                    'c' => {
                        show_bytes = true;
                        any_selector = true;
                    }
                    _ => {
                        eprintln!("wc: unknown option '-{}'", flag);
                        usage();
                        return 2;
                    }
                }
            }
        } else {
            files.push(arg.clone());
        }
    }

    if !any_selector {
        show_lines = true;
        show_words = true;
        show_bytes = true;
    }
    if files.is_empty() {
        files.push(String::from("-"));
    }

    let mut out = BufWriter::new(io::stdout());
    let mut total = Counts::default();
    let mut status = 0;
    let mut counted = 0usize;

    for file in &files {
        let result = if file == "-" {
            let mut stdin = io::stdin();
            let mut reader = BufReader::new(&mut stdin);
            count(&mut reader)
        } else {
            match File::open(file) {
                Ok(input) => {
                    let mut reader = BufReader::new(input);
                    count(&mut reader)
                }
                Err(error) => {
                    eprintln!("wc: {}: {}", file, error);
                    status = 1;
                    continue;
                }
            }
        };

        match result {
            Ok(counts) => {
                total.add(counts);
                counted += 1;
                if let Err(error) = print_counts(
                    &mut out,
                    counts,
                    show_lines,
                    show_words,
                    show_bytes,
                    if file == "-" { "" } else { file.as_str() },
                ) {
                    eprintln!("wc: stdout: {}", error);
                    return 1;
                }
            }
            Err(error) => {
                eprintln!("wc: {}: {}", file, error);
                status = 1;
            }
        }
    }

    if counted > 1 {
        if let Err(error) =
            print_counts(&mut out, total, show_lines, show_words, show_bytes, "total")
        {
            eprintln!("wc: stdout: {}", error);
            return 1;
        }
    }

    if let Err(error) = out.flush() {
        eprintln!("wc: stdout: {}", error);
        status = 1;
    }
    status
}
