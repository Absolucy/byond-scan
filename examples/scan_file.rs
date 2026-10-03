// SPDX-License-Identifier: MPL-2.0
//! Checks whether a byte mask matches exactly once in a BYOND binary on disk.
//!
//! ```text
//! cargo run --example scan_file -- byondcore.dll "55 8B EC 8B 45 08 ?? ??"
//! ```
//!
//! The scanner refuses a mask that matches zero times or more than once, so
//! this is the first thing to check about a new one.
//!
//! This reads the file as one flat run of bytes. The printed number is an
//! offset into the file, not an address, and a match in data counts the same
//! as one in code.

use byond_scan::{Module, Signature, SignatureTreatment};
use std::process::ExitCode;

fn main() -> ExitCode {
	let mut args = std::env::args().skip(1);
	let (Some(path), Some(mask)) = (args.next(), args.next()) else {
		eprintln!("usage: scan_file <byondcore.dll | libbyond.so> \"<mask>\"");
		return ExitCode::FAILURE;
	};
	let bytes = match std::fs::read(&path) {
		Ok(bytes) => bytes,
		Err(error) => {
			eprintln!("failed to read {path}: {error}");
			return ExitCode::FAILURE;
		}
	};

	// `Module` wants `'static` bytes; a one-shot tool can just leak them
	let module = Module::from_parts(0, 0, bytes.leak());
	match Signature::new(SignatureTreatment::NoOffset, &mask).find(&module, "mask") {
		Ok(offset) => {
			println!("one match, at file offset {offset:#x}");
			ExitCode::SUCCESS
		}
		Err(error) => {
			eprintln!("{error}");
			ExitCode::FAILURE
		}
	}
}
