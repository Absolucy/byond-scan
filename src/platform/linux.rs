// SPDX-License-Identifier: MPL-2.0
use super::LocatedModule;
use crate::module::AddressRange;
use std::ffi::{CStr, c_void};

const MODULE_NAME: &[u8] = b"libbyond.so";

/// finds the loaded `libbyond.so`: its executable segment and where it got
/// loaded.
pub fn locate() -> Option<LocatedModule> {
	let seg = find_segment()?;
	let live = unsafe {
		std::slice::from_raw_parts(seg.exec_range.start as *const u8, seg.exec_range.len())
	};
	Some(LocatedModule {
		base: seg.base,
		range_start: seg.exec_range.start,
		scan_range: Box::leak(live.into()),
		executable_ranges: seg.executable_ranges,
		writable_ranges: seg.writable_ranges,
	})
}

pub fn find_export(sym: &CStr) -> *const c_void {
	// the null handle searches the already-loaded process image
	unsafe { libc::dlsym(std::ptr::null_mut(), sym.as_ptr()) }
}

#[derive(Clone, Copy)]
struct Segment {
	base: usize,
	exec_range: AddressRange,
	executable_ranges: &'static [AddressRange],
	writable_ranges: &'static [AddressRange],
}

extern "C" fn phdr_cb(info: *mut libc::dl_phdr_info, _size: usize, data: *mut c_void) -> i32 {
	unsafe {
		let info = &*info;
		let name = CStr::from_ptr(info.dlpi_name);
		if !name.to_bytes().ends_with(MODULE_NAME) {
			return 0;
		}
		let out = &mut *(data as *mut Option<Segment>);
		let base = info.dlpi_addr as usize;
		let headers = std::slice::from_raw_parts(info.dlpi_phdr, info.dlpi_phnum as usize);
		let executable: Vec<AddressRange> = headers
			.iter()
			.filter(|p| p.p_type == libc::PT_LOAD && p.p_flags & libc::PF_X != 0)
			.map(|p| AddressRange::new(base + p.p_vaddr as usize, p.p_memsz as usize))
			.collect();
		let writable: Vec<AddressRange> = headers
			.iter()
			.filter(|p| p.p_type == libc::PT_LOAD && p.p_flags & libc::PF_W != 0)
			.map(|p| AddressRange::new(base + p.p_vaddr as usize, p.p_memsz as usize))
			.collect();
		if let Some(exec_range) = executable.first().copied()
			&& !writable.is_empty()
		{
			*out = Some(Segment {
				base,
				exec_range,
				executable_ranges: Box::leak(executable.into_boxed_slice()),
				writable_ranges: Box::leak(writable.into_boxed_slice()),
			});
		}
		1
	}
}

fn find_segment() -> Option<Segment> {
	let mut found: Option<Segment> = None;
	unsafe {
		libc::dl_iterate_phdr(Some(phdr_cb), (&mut found as *mut Option<Segment>).cast());
	}
	found
}
