# AGENTS.md

Guidance for coding agents working in this repository.

## What this is

A library that finds functions, globals, and struct field offsets inside
BYOND's `byondcore.dll` / `libbyond.so` at runtime. A caller describes a target
with a `Recipe` (a byte mask plus which instruction operand to read), and the
scanner returns the address. `README.md` explains the recipe model; read it
before changing `recipe.rs`.

## The one rule

**No recipes for real BYOND builds live here.** This crate is the scanner
only. Masks, build ranges, and expected addresses belong to whoever uses the
library. The fake module in `examples/resolve_recipes.rs` and the byte arrays
in the unit tests are hand-written on purpose.

## Commands

```sh
cargo +nightly fmt                # nightly is required, .rustfmt.toml uses unstable options
cargo clippy --all-targets -- -D warnings
cargo nextest run                 # unit tests
cargo test --doc                  # the README's code blocks
cargo run --example resolve_recipes
```

Plain `cargo fmt` silently ignores half of `.rustfmt.toml` and reformats the
tree into a shape the next nightly run undoes.

Add `--target i686-pc-windows-msvc` or `--target i686-unknown-linux-gnu` to
check the targets that ship. CI (`.github/workflows/build.yml`) runs clippy,
rustfmt, the tests, and the example on both.

### Checking a change against real binaries

The tests never touch a real BYOND binary. After changing how masks match, run
a mask you know against a real file and check it still matches once:

```sh
cargo run --example scan_file -- <byondcore.dll | libbyond.so> "<mask>"
```

That only covers mask matching. A change to how operands are read or how calls
are followed has no real-binary check in this repo, so say so in your report
instead of calling it verified.

## Layout

| File | What it is for |
|---|---|
| `src/recipe.rs` | The `Recipe` type and `resolve_recipe`, which runs anchor, hops, extract |
| `src/signature.rs` | Byte-mask parsing and the unique-match search |
| `src/disasm.rs` | Reading an operand or following a call, on top of `iced-x86` |
| `src/decode.rs` | Shared decoder setup and operand helpers, crate-private |
| `src/validation.rs` | Structural checks for a result on a build nobody verified |
| `src/module.rs` | `Module`: the bytes to scan plus its executable and writable ranges |
| `src/platform/` | Finding the loaded module and its exports through the OS |
| `src/version.rs` | The running BYOND version, via `Byond_GetVersion` |
| `src/error.rs` | The error enum |
| `examples/` | `resolve_recipes` (self-checking, no BYOND) and `scan_file` (one mask against a file) |

## Things that are easy to break

- **32-bit only.** Every decoder is created with bitness 32, and operands are
  read as 4-byte values. Do not add a 64-bit path.
- **`src/platform/` is the only platform-specific code.** Everything else has
  no `#[cfg]`, which is why the Linux scanning logic can be tested on Windows.
  Keep it that way.
- **A mask must match exactly once.** `unique_match` returns `Ambiguous` on a
  second hit. Never make it return the first match.
- **No module's bytes sit at the addresses it reports.** A `Module` from
  `from_parts` holds file bytes. One from `Module::current()` holds a copy of
  the loaded module, made once, with the writable sections (and on Windows the
  PE headers) left as zeros. Either way the reported address is `range_start`.
  Read through `module.range()` with an offset. Never dereference an address
  the scanner computed.
- **Never make a slice over live BYOND memory.** BYOND writes its globals and
  hooks patch its code, and a `&[u8]` promises the compiler nobody does. That
  is why `src/platform/` copies.
- **Modules leak.** They hold `'static` slices, and `Module::current()` leaks
  its copy of the module. That is fine for a module that lives as long as the
  process, which is every real use.
- **Offline modules never ask the OS for exports.** `find_export` on a module
  from `from_parts` only looks in the table given to `with_exports`. The OS
  would answer for whatever BYOND is loaded in the current process instead.
- **Function scans stop at the function's end.** `decode::function_instructions`
  stops at the first `ret` or `int3` that no earlier branch jumps past. A `jmp`
  is not an end, because real recipes anchor inside one `switch` case and count
  calls through the cases after it. Treating `jmp` as an end broke eight of
  them when it was tried.
- **A new way to find or read something is one enum variant** (`Anchor`,
  `Extract`, `SignatureTreatment`) handled in one `match`. Renaming or
  removing a variant breaks every recipe list written against this crate, so
  treat those enums as public API.

## Minimum Rust version

`rust-version` in `Cargo.toml` is the only place the number lives. The `msrv`
CI job reads it from there and builds on exactly that compiler. Using a newer
language or standard library feature fails that job until you raise the number
on purpose:

```sh
cargo msrv verify -- cargo check --all-targets
```

`Cargo.lock` is committed so the dependency versions the minimum was measured
with are the ones everyone gets.

## Style

- Tabs. `// SPDX-License-Identifier: MPL-2.0` on line 1 of every `.rs` file.
- One block of `use` lines per file, no blank lines between them.
- Explicit imports, no glob or prelude imports.
- Comments say why, briefly. No banners or section dividers.
- Public constructors and pure functions get `#[must_use]`.
