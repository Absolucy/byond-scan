// SPDX-License-Identifier: MPL-2.0
use crate::{
	error::{Error, Result},
	platform,
};
use std::{ffi::CStr, sync::OnceLock};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressRange {
	pub start: usize,
	pub end: usize,
}

impl AddressRange {
	#[must_use]
	pub const fn new(start: usize, len: usize) -> Self {
		Self {
			start,
			end: start.saturating_add(len),
		}
	}

	#[must_use]
	pub const fn contains(self, address: usize) -> bool {
		self.start <= address && address < self.end
	}

	#[must_use]
	pub const fn len(self) -> usize {
		self.end.saturating_sub(self.start)
	}

	#[must_use]
	pub const fn is_empty(self) -> bool {
		self.start >= self.end
	}
}

#[cfg(target_os = "windows")]
pub const MODULE_NAME: &str = "byondcore.dll";
#[cfg(not(target_os = "windows"))]
pub const MODULE_NAME: &str = "libbyond.so";

/// a BYOND module and the bytes to scan in it.
///
/// `range_start` is kept apart from where the slice really sits in memory.
/// that's what lets a module built from a file pretend its bytes live at the
/// addresses the file says they should. a live module works the same way:
/// its slice is a copy, and `range_start` is where BYOND really has them.
#[derive(Clone, Copy)]
pub struct Module {
	base: usize,
	range_start: usize,
	range: &'static [u8],
	executable_ranges: &'static [AddressRange],
	writable_ranges: &'static [AddressRange],
	exports: Exports,
}

#[derive(Clone, Copy)]
enum Exports {
	/// a live module asks the OS.
	Loader,
	/// a module built from a file only knows the table it was handed. asking
	/// the OS would answer for whatever BYOND happens to be loaded instead.
	Table(&'static [(&'static CStr, usize)]),
}

impl Module {
	/// finds BYOND's module in the current process.
	///
	/// the bytes it scans are a copy, taken on the first call that finds
	/// BYOND. later calls hand back that same module, so the copy is only
	/// ever made once.
	pub fn current() -> Result<Self> {
		static CURRENT: OnceLock<Module> = OnceLock::new();
		if let Some(module) = CURRENT.get() {
			return Ok(*module);
		}
		let located = platform::locate().ok_or(Error::ModuleNotFound)?;
		Ok(*CURRENT.get_or_init(|| Self {
			base: located.base,
			range_start: located.range_start,
			range: located.scan_range,
			executable_ranges: located.executable_ranges,
			writable_ranges: located.writable_ranges,
			exports: Exports::Loader,
		}))
	}

	/// builds a module out of bytes you hand it, no BYOND needed.
	///
	/// `range_start` is the address that `range[0]` stands for. pass a `base`
	/// of 0 if you want results left as the addresses in the file.
	///
	/// this leaks a small allocation per call. fine for a module that lives
	/// as long as the process, which is every real use.
	#[must_use]
	pub fn from_parts(base: usize, range_start: usize, range: &'static [u8]) -> Self {
		let executable_ranges =
			Box::leak(vec![AddressRange::new(range_start, range.len())].into_boxed_slice());
		Self {
			base,
			range_start,
			range,
			executable_ranges,
			writable_ranges: &[],
			exports: Exports::Table(&[]),
		}
	}

	/// like [`Module::from_parts`], but you also say which address ranges
	/// are executable and which are writable.
	#[must_use]
	pub fn from_parts_with_ranges(
		base: usize,
		range_start: usize,
		range: &'static [u8],
		executable_ranges: &'static [AddressRange],
		writable_ranges: &'static [AddressRange],
	) -> Self {
		Self {
			base,
			range_start,
			range,
			executable_ranges,
			writable_ranges,
			exports: Exports::Table(&[]),
		}
	}

	/// attaches an export table you parsed out of a file yourself.
	///
	/// the parsing is left to you on purpose, so a PE/ELF parser never ends
	/// up linked into a plugin that only scans a live process.
	#[must_use]
	pub fn with_exports(mut self, exports: &'static [(&'static CStr, usize)]) -> Self {
		self.exports = Exports::Table(exports);
		self
	}

	#[must_use]
	pub fn find_export(&self, symbol: &CStr) -> Option<usize> {
		match self.exports {
			Exports::Table(table) => table
				.iter()
				.find(|(name, _)| *name == symbol)
				.map(|(_, address)| *address),
			Exports::Loader => {
				let pointer = platform::find_export(symbol);
				(!pointer.is_null()).then_some(pointer as usize)
			}
		}
	}

	/// where the module is loaded. only needed to turn an offset you pinned
	/// by hand into an address.
	#[must_use]
	pub fn base(&self) -> usize {
		self.base
	}

	#[must_use]
	pub fn range(&self) -> &'static [u8] {
		self.range
	}

	/// the address that `range()[0]` stands for.
	#[must_use]
	pub fn range_start(&self) -> usize {
		self.range_start
	}

	#[must_use]
	pub fn executable_ranges(&self) -> &'static [AddressRange] {
		self.executable_ranges
	}

	#[must_use]
	pub fn is_executable(&self, address: usize) -> bool {
		self.executable_ranges
			.iter()
			.any(|range| range.contains(address))
	}

	#[must_use]
	pub fn is_writable(&self, address: usize) -> bool {
		self.writable_ranges
			.iter()
			.any(|range| range.contains(address))
	}
}

#[cfg(test)]
mod tests {
	use super::Module;
	use std::ffi::CStr;

	#[test]
	fn attached_exports_are_used_instead_of_the_loader() {
		static TABLE: &[(&CStr, usize)] = &[
			(c"ByondValue_IncRef", 0x539730),
			(c"Byond_ListRemove", 0x53C500),
		];
		let module = Module::from_parts(0, 0x400000, &[0x90]).with_exports(TABLE);
		assert_eq!(module.find_export(c"ByondValue_IncRef"), Some(0x539730));
		assert_eq!(module.find_export(c"Byond_ListRemove"), Some(0x53C500));
	}

	// only bites on linux, where the loader really can resolve `malloc`.
	// windows looks in byondcore.dll, which no test process has loaded
	#[test]
	fn a_module_from_bytes_never_asks_the_loader() {
		let module = Module::from_parts(0, 0x400000, &[0x90]);
		assert_eq!(module.find_export(c"malloc"), None);
	}

	#[test]
	fn an_absent_export_does_not_fall_back_to_the_loader() {
		static TABLE: &[(&CStr, usize)] = &[(c"ByondValue_IncRef", 0x539730)];
		let module = Module::from_parts(0, 0x400000, &[0x90]).with_exports(TABLE);
		assert_eq!(module.find_export(c"Byond_ListRemove"), None);
	}
}
