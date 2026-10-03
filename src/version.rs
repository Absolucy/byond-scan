// SPDX-License-Identifier: MPL-2.0
use crate::{
	error::{Error, Result},
	platform,
};
use std::{
	ffi::{CStr, c_void},
	sync::atomic::{AtomicU64, Ordering},
};

// plain C name, shared by both platforms
const VERSION_EXPORT: &CStr = c"Byond_GetVersion";

// no real build is 0; one atomic keeps the pair coherent
static CACHED: AtomicU64 = AtomicU64::new(0);

type GetVersionFn = unsafe extern "C" fn(*mut u32, *mut u32);

/// the running BYOND's `(version, build)`. cached after the first call.
pub fn version() -> Result<(u32, u32)> {
	let cached = CACHED.load(Ordering::Relaxed);
	if cached != 0 {
		return Ok(((cached >> 32) as u32, cached as u32));
	}
	let sym = platform::find_export(VERSION_EXPORT);
	if sym.is_null() {
		return Err(Error::ExportNotFound("Byond_GetVersion"));
	}
	let get_version = unsafe { std::mem::transmute::<*const c_void, GetVersionFn>(sym) };
	let mut version: u32 = 0;
	let mut build: u32 = 0;
	unsafe { get_version(&mut version, &mut build) };
	CACHED.store(
		(u64::from(version) << 32) | u64::from(build),
		Ordering::Relaxed,
	);
	Ok((version, build))
}
