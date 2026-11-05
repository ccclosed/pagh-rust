# pagh-rust — Rust SDK и std-слой для pagh-riscv

Нативный Rust для pagh-riscv: программы компилируются `rustc` под
`riscv64gc-unknown-none-elf`, линкуются с `libpagh` и запускаются в U-mode через
`run /mnt/...`. Полный `rustc` на борту невозможен (LLVM + host-OS), но
**язык Rust, generics, traits, closures, iterators, `alloc`, `String`, `Vec`,
collections и `format!`** работают — не хватает только `std`-обвязки, которую
этот репозиторий и даёт.

## Что здесь

- `pagh_std` — std-подобный слой поверх `libpagh`: `io` (Read/Write/Seek,
  stdin/stdout/stderr, BufReader/BufWriter), `fs` (File, OpenOptions, Dir,
  metadata), `env`, `process::exit`, `time` (Instant/Duration/SystemTime),
  `collections` (HashMap/BTreeMap/VecDeque из alloc), `fmt`-макросы,
  `println!/print!/eprintln!/dbg!`, `panic`.
- `examples/` — реальные программы (cat, wc, find), чтобы проверять не «hello»,
  а файловые API и итераторы.
- `build.sh` — сборка примера в RV64 ELF, пригодный для `run`.
- Тесты: host-проверки чистой логики + живой запуск в QEMU.

## Чего нет и почему

Нет потоков/`std::thread`, процессов/`std::process::Command`, сети
(`TcpStream`), динамической линковки, `std::fs`-путей с `OsStr` — в ABI пока нет
`fork/exec`, `mmap`, сокетов и TLS. Это отдельные майлстоуны ядра; SDK растёт
вместе с ними. Обещать «полный std» без них нельзя.

## Сборка

```sh
./build.sh examples/cat.rs /tmp/cat.elf
# скопировать cat.elf в /mnt и в гостя:
run /mnt/cat /mnt/file.txt
```
