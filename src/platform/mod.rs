// SPDX-License-Identifier: MPL-2.0
//! the only place that talks to the OS loader. everything else in the crate
//! gets to have zero `#[cfg]` because of it.

use crate::module::AddressRange;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::{find_export, locate};

#[cfg(not(target_os = "windows"))]
mod linux;
#[cfg(not(target_os = "windows"))]
pub use linux::{find_export, locate};

pub(crate) struct LocatedModule {
	pub base: usize,
	/// the live address that `scan_range[0]` was copied from.
	pub range_start: usize,
	/// a copy of the module's bytes, never a slice over the live mapping.
	/// BYOND rewrites its globals and hooks patch its code, and a shared slice
	/// would be promising the compiler that neither ever happens.
	pub scan_range: &'static [u8],
	pub executable_ranges: &'static [AddressRange],
	pub writable_ranges: &'static [AddressRange],
}
