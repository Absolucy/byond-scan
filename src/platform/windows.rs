// SPDX-License-Identifier: MPL-2.0
use super::LocatedModule;
use crate::module::AddressRange;
use std::ffi::{CStr, c_char, c_void};

const MODULE_NAME: &CStr = c"byondcore.dll";
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

unsafe extern "system" {
	fn GetModuleHandleA(name: *const c_char) -> usize;
	fn GetProcAddress(module: usize, name: *const c_char) -> *const c_void;
}

/// finds the loaded `byondcore.dll`. the whole image gets scanned, not just
/// the code, so a mask has to be unique across all of it. the PE headers
/// and the writable sections are in there as zeros.
pub fn locate() -> Option<LocatedModule> {
	let base = unsafe { GetModuleHandleA(MODULE_NAME.as_ptr()) };
	if base == 0 {
		return None;
	}
	scan_ranges(base)
}

pub fn find_export(sym: &CStr) -> *const c_void {
	let base = unsafe { GetModuleHandleA(MODULE_NAME.as_ptr()) };
	if base == 0 {
		return std::ptr::null();
	}
	unsafe { GetProcAddress(base, sym.as_ptr()) }
}

/// reads the PE headers by hand to learn which sections are executable and
/// which are writable. the `validation` checks need that.
fn scan_ranges(base: usize) -> Option<LocatedModule> {
	unsafe {
		// IMAGE_DOS_HEADER.e_lfanew, an i32 at +0x3C, points at the NT headers
		let e_lfanew = ((base + 0x3C) as *const i32).read_unaligned();
		let nt = base + e_lfanew as usize;
		let section_count = ((nt + 0x06) as *const u16).read_unaligned() as usize;
		let optional_size = ((nt + 0x14) as *const u16).read_unaligned() as usize;
		// OptionalHeader starts 0x18 past the NT signature (4 sig + 0x14
		// FileHeader), and SizeOfImage is at OptionalHeader +0x38, so NT +0x50
		let len = ((nt + 0x50) as *const u32).read_unaligned() as usize;
		if len == 0 {
			return None;
		}
		let section_table = nt + 0x18 + optional_size;
		let mut executable = Vec::new();
		let mut writable = Vec::new();
		let mut image = vec![0u8; len];
		for index in 0..section_count {
			let section = section_table + index * 40;
			let virtual_size = ((section + 0x08) as *const u32).read_unaligned() as usize;
			let virtual_address = ((section + 0x0C) as *const u32).read_unaligned() as usize;
			let raw_size = ((section + 0x10) as *const u32).read_unaligned() as usize;
			let characteristics = ((section + 0x24) as *const u32).read_unaligned();
			let size = virtual_size.max(raw_size);
			if size == 0 {
				continue;
			}
			let range = AddressRange::new(base + virtual_address, size);
			if characteristics & IMAGE_SCN_MEM_EXECUTE != 0 {
				executable.push(range);
			}
			if characteristics & IMAGE_SCN_MEM_WRITE != 0 {
				// left as zeros. BYOND can be writing these from another
				// thread right now, so even copying them would be a race
				writable.push(range);
			} else if let Some(copy) = image.get_mut(virtual_address..) {
				let len = size.min(copy.len());
				let live = std::slice::from_raw_parts(range.start as *const u8, len);
				copy[..len].copy_from_slice(live);
			}
		}
		if executable.is_empty() || writable.is_empty() {
			return None;
		}
		Some(LocatedModule {
			base,
			range_start: base,
			scan_range: Box::leak(image.into_boxed_slice()),
			executable_ranges: Box::leak(executable.into_boxed_slice()),
			writable_ranges: Box::leak(writable.into_boxed_slice()),
		})
	}
}
