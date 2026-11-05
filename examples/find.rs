//! `find` — walk directories with `ReadDir`, `Path::join` and `Metadata`.
//!
//! Supported: `find [path...] [-type f|d|l] [-maxdepth N] [-ls]`.
//! Entries are sorted per directory for deterministic output. Symlinks found
//! during traversal are printed but never followed; a path named on the command
//! line is resolved with `metadata`, and the ABI has no `lstat`, so a symlink
//! root is followed. `-ls` prints `mode size ino path`.

#![no_std]
#![no_main]

use pagh_std::fs::{self, DirEntry, FileType};
use pagh_std::prelude::*;

#[derive(Clone, Copy, PartialEq, Eq)]
enum TypeFilter {
    Any,
    File,
    Dir,
    Symlink,
}

impl TypeFilter {
    fn matches(self, file_type: FileType) -> bool {
        match self {
            TypeFilter::Any => true,
            TypeFilter::File => file_type.is_file(),
            TypeFilter::Dir => file_type.is_dir(),
            TypeFilter::Symlink => file_type.is_symlink(),
        }
    }
}

struct Options {
    filter: TypeFilter,
    maxdepth: usize,
    long: bool,
}

fn usage() {
    eprintln!("usage: find [path...] [-type f|d|l] [-maxdepth N] [-ls]");
}

fn parse_type(value: &str) -> Option<TypeFilter> {
    match value {
        "f" => Some(TypeFilter::File),
        "d" => Some(TypeFilter::Dir),
        "l" => Some(TypeFilter::Symlink),
        _ => None,
    }
}

struct Walker<'a, W: Write> {
    out: &'a mut W,
    options: &'a Options,
    status: i32,
}

impl<W: Write> Walker<'_, W> {
    fn emit(&mut self, path: &Path, file_type: FileType) -> io::Result<()> {
        if !self.options.filter.matches(file_type) {
            return Ok(());
        }
        if self.options.long {
            match fs::metadata(path) {
                Ok(metadata) => writeln!(
                    self.out,
                    "{:06o} {:>8} {:>8} {}",
                    metadata.mode(),
                    metadata.len(),
                    metadata.ino(),
                    path.display()
                ),
                Err(error) => {
                    eprintln!("find: {}: {}", path.display(), error);
                    self.status = 1;
                    Ok(())
                }
            }
        } else {
            writeln!(self.out, "{}", path.display())
        }
    }

    fn walk(&mut self, path: &Path, depth: usize, emit_self: bool) -> io::Result<()> {
        // `metadata` follows a symlink; command-line roots are followed by
        // design. Entries discovered by the iterator use `getdents64`'s type
        // for filtering and are never traversed when they are links.
        let metadata = match fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(error) => {
                eprintln!("find: {}: {}", path.display(), error);
                self.status = 1;
                return Ok(());
            }
        };

        if emit_self {
            self.emit(path, metadata.file_type())?;
        }
        if !metadata.is_dir() || depth >= self.options.maxdepth {
            return Ok(());
        }

        let mut entries: Vec<DirEntry> = Vec::new();
        match fs::read_dir(path) {
            Ok(iterator) => {
                for entry in iterator {
                    match entry {
                        Ok(entry) => entries.push(entry),
                        Err(error) => {
                            eprintln!("find: {}: {}", path.display(), error);
                            self.status = 1;
                        }
                    }
                }
            }
            Err(error) => {
                eprintln!("find: {}: {}", path.display(), error);
                self.status = 1;
                return Ok(());
            }
        }
        entries.sort_by(|left, right| left.file_name().cmp(right.file_name()));

        for entry in &entries {
            let file_type = entry.file_type();
            self.emit(entry.path(), file_type)?;
            if file_type.is_dir() {
                self.walk(entry.path(), depth + 1, false)?;
            }
        }
        Ok(())
    }
}

#[no_mangle]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let args: Vec<String> = env::args().collect();
    let mut paths: Vec<PathBuf> = Vec::new();
    let mut filter = TypeFilter::Any;
    let mut maxdepth = usize::MAX;
    let mut long = false;
    let mut options_done = false;
    let mut index = 1usize;

    while index < args.len() {
        let argument = args[index].as_str();
        if options_done {
            paths.push(PathBuf::from(argument));
            index += 1;
            continue;
        }
        match argument {
            "--" => {
                options_done = true;
                index += 1;
            }
            "-h" | "--help" => {
                usage();
                return 0;
            }
            "-type" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    eprintln!("find: -type needs an argument");
                    usage();
                    return 2;
                };
                let Some(parsed) = parse_type(value.as_str()) else {
                    eprintln!("find: -type must be f, d or l (got '{}')", value);
                    return 2;
                };
                filter = parsed;
                index += 1;
            }
            "-maxdepth" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    eprintln!("find: -maxdepth needs an argument");
                    usage();
                    return 2;
                };
                match value.parse::<usize>() {
                    Ok(parsed) => maxdepth = parsed,
                    Err(_) => {
                        eprintln!("find: -maxdepth expects a non-negative integer");
                        return 2;
                    }
                }
                index += 1;
            }
            "-ls" => {
                long = true;
                index += 1;
            }
            other if other.starts_with('-') && other != "-" => {
                eprintln!("find: unknown option '{}'", other);
                usage();
                return 2;
            }
            other => {
                paths.push(PathBuf::from(other));
                index += 1;
            }
        }
    }

    if paths.is_empty() {
        paths.push(PathBuf::from("."));
    }

    let options = Options {
        filter,
        maxdepth,
        long,
    };
    let mut out = BufWriter::new(io::stdout());
    let mut status;

    {
        let mut walker = Walker {
            out: &mut out,
            options: &options,
            status: 0,
        };
        for path in &paths {
            if let Err(error) = walker.walk(path, 0, true) {
                eprintln!("find: {}: {}", path.display(), error);
                walker.status = 1;
            }
        }
        status = walker.status;
    }

    if let Err(error) = out.flush() {
        eprintln!("find: stdout: {}", error);
        status = 1;
    }
    status
}
