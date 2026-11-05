//! Diagnostic probe: exercise the filesystem mutation API end to end.
//!
//! Not a real program. It creates a scratch tree under `/mnt`, writes, copies,
//! renames, hard-links, symlinks, reads links and metadata, truncates, removes
//! a tree, and checks the typed `Unsupported` answers for the operations the
//! ABI cannot express.

#![no_std]
#![no_main]

use pagh_std::fs::{self, OpenOptions};
use pagh_std::io::ErrorKind;
use pagh_std::prelude::*;

const DIR: &str = "/mnt/sdk-scratch";

fn run() -> io::Result<()> {
    let _ = fs::remove_dir_all(DIR);
    fs::create_dir_all(DIR)?;
    let first = format!("{DIR}/a.txt");
    fs::write(&first, b"alpha")?;

    let text = fs::read_to_string(&first)?;
    println!("fsops: read={}", text);

    let copied = fs::copy("/mnt/sdk-scratch/a.txt", "/mnt/sdk-scratch/b.txt")?;
    println!("fsops: copied={}", copied);

    fs::rename("/mnt/sdk-scratch/b.txt", "/mnt/sdk-scratch/c.txt")?;
    fs::hard_link("/mnt/sdk-scratch/a.txt", "/mnt/sdk-scratch/hard.txt")?;
    fs::symlink("a.txt", "/mnt/sdk-scratch/link")?;
    println!(
        "fsops: readlink={}",
        fs::read_link("/mnt/sdk-scratch/link")?
    );

    let metadata = fs::metadata("/mnt/sdk-scratch/hard.txt")?;
    println!(
        "fsops: size={} mode={:#o} ino={} kind={:?}",
        metadata.len(),
        metadata.mode(),
        metadata.ino(),
        metadata.file_type()
    );

    let mut options = OpenOptions::new();
    options.write(true).append(true).create(true);
    let mut file = options.open("/mnt/sdk-scratch/a.txt")?;
    file.write_all(b"-appended")?;
    println!("fsops: appended_len={}", file.metadata()?.len());
    file.set_len(5)?;
    println!("fsops: truncated_len={}", file.metadata()?.len());
    println!(
        "fsops: sync_all unsupported={}",
        matches!(file.sync_all(), Err(error) if error.kind() == ErrorKind::Unsupported)
    );

    let create_new = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open("/mnt/sdk-scratch/new.txt");
    println!(
        "fsops: create_new unsupported={}",
        matches!(create_new, Err(error) if error.kind() == ErrorKind::Unsupported)
    );
    let symlink_meta = fs::symlink_metadata("/mnt/sdk-scratch/link");
    println!(
        "fsops: symlink_metadata unsupported={}",
        matches!(symlink_meta, Err(error) if error.kind() == ErrorKind::Unsupported)
    );

    println!(
        "fsops: canonicalize={}",
        fs::canonicalize("/mnt/sdk-scratch/../sdk-scratch/./a.txt")?.display()
    );

    fs::create_dir("/mnt/sdk-scratch/sub")?;
    fs::remove_dir("/mnt/sdk-scratch/sub")?;
    fs::remove_file("/mnt/sdk-scratch/link")?;
    fs::remove_dir_all(DIR)?;
    let removed = matches!(fs::metadata(DIR), Err(error) if error.kind() == ErrorKind::NotFound);
    println!("fsops: removed={}", removed);
    println!("fsops: ok");
    Ok(())
}

#[no_mangle]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    match run() {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("fsops: {}", error);
            1
        }
    }
}
