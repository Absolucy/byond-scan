// SPDX-License-Identifier: MPL-2.0
use crate::{
	error::{Error, Result},
	module::Module,
};

/// what to do with a mask match to get an address out of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureTreatment {
	/// the match is the address.
	NoOffset,
	/// read the 32-bit value sitting `n` bytes into the match.
	OffsetByInt(isize),
	/// the match starts with a `call`. you get the function it calls.
	OffsetByCall,
	/// start at an earlier landmark instead of at the match itself.
	///
	/// for a function whose only distinctive bytes are near its end. the main
	/// mask pins down the function, then this walks back to a landmark
	/// (normally the first instructions of the function), so the result still
	/// means "the start of the function". everything that counts
	/// instructions from there assumes that.
	///
	/// why a second mask and not a fixed distance: the gap moves. one real
	/// BYOND function grew an extra check between builds, which pushed its
	/// distinctive bytes from 6 bytes past the start to 9. searching for the
	/// landmark soaks that up.
	///
	/// the landmark has to match exactly once in the `window` bytes before
	/// the main match. so walking back into the function next door is a loud
	/// error, not a quiet wrong answer.
	RewindTo { mask: &'static str, window: usize },
}

pub struct Signature {
	pub treatment: SignatureTreatment,
	pub bytes: Vec<Option<u8>>,
}

impl Signature {
	/// takes a mask of hex bytes separated by spaces, like `"A1 ?? ?? ?? ??"`.
	#[must_use]
	pub fn new(treatment: SignatureTreatment, mask: &str) -> Self {
		Self {
			treatment,
			bytes: parse_mask(mask),
		}
	}

	/// finds the one match and applies the treatment. zero matches or more
	/// than one is an error.
	pub fn find(&self, module: &Module, name: &'static str) -> Result<usize> {
		let hit = unique_match(module.range(), &self.bytes, name)?;
		let addr = module.range_start() + hit;
		self.apply(module, addr, name)
	}

	fn apply(&self, module: &Module, addr: usize, name: &'static str) -> Result<usize> {
		match self.treatment {
			SignatureTreatment::NoOffset => Ok(addr),
			SignatureTreatment::OffsetByInt(n) => {
				// BYOND is 32-bit, so the operand is always a 4-byte pointer
				read_dword(module, (addr as isize + n) as usize, name).map(|v| v as usize)
			}
			SignatureTreatment::OffsetByCall => {
				let rel = read_dword(module, addr + 1, name)? as i32;
				Ok((addr + 5).wrapping_add_signed(rel as isize))
			}
			SignatureTreatment::RewindTo { mask, window } => {
				let landmark = parse_mask(mask);
				let end = addr
					.checked_sub(module.range_start())
					.ok_or(Error::NotFound(name))?;
				let start = end.saturating_sub(window);
				let hay = module
					.range()
					.get(start..end)
					.ok_or(Error::NotFound(name))?;
				let hit = unique_match(hay, &landmark, name)?;
				Ok(module.range_start() + start + hit)
			}
		}
	}
}

/// reads 4 bytes out of the module's byte slice. it never dereferences
/// `address` itself.
///
/// a module built from a file doesn't really live at the addresses it
/// claims, so `address` points at nothing. going through the slice also
/// means a read near the end can't run off it.
fn read_dword(module: &Module, address: usize, name: &'static str) -> Result<u32> {
	let range = module.range();
	let offset = address
		.checked_sub(module.range_start())
		.ok_or(Error::NotFound(name))?;
	let bytes = range
		.get(offset..offset + 4)
		.ok_or(Error::NotFound(name))?
		.try_into()
		.map_err(|_| Error::NotFound(name))?;
	Ok(u32::from_le_bytes(bytes))
}

/// turns a mask string into bytes, with `None` for each `??`. heads up: a
/// token that isn't valid hex also becomes a wildcard, not an error.
#[must_use]
pub fn parse_mask(mask: &str) -> Vec<Option<u8>> {
	mask.split_whitespace()
		.map(|tok| match tok {
			"??" => None,
			_ => u8::from_str_radix(tok, 16).ok(),
		})
		.collect()
}

/// finds the one place the mask matches. no match and two matches are both
/// errors.
fn unique_match(haystack: &[u8], sig: &[Option<u8>], name: &'static str) -> Result<usize> {
	if sig.is_empty() || haystack.len() < sig.len() {
		return Err(Error::NotFound(name));
	}
	let mut found: Option<usize> = None;
	for start in 0..=haystack.len() - sig.len() {
		let matches = sig
			.iter()
			.zip(&haystack[start..])
			.all(|(want, got)| want.is_none_or(|b| b == *got));
		if matches {
			if found.is_some() {
				return Err(Error::Ambiguous(name));
			}
			found = Some(start);
		}
	}
	found.ok_or(Error::NotFound(name))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parse_mask_roundtrips_bytes_and_wildcards() {
		assert_eq!(parse_mask("A1 ?? ?? ?? ??"), vec![
			Some(0xA1),
			None,
			None,
			None,
			None
		]);
		assert_eq!(parse_mask("00 ff"), vec![Some(0x00), Some(0xFF)]);
	}

	#[test]
	fn unique_match_finds_single() {
		let hay = [0x00, 0xA1, 0xDE, 0xAD, 0xBE, 0xEF, 0x00];
		let sig = parse_mask("A1 ?? ?? ?? ??");
		assert_eq!(unique_match(&hay, &sig, "t"), Ok(1));
	}

	#[test]
	fn unique_match_rejects_ambiguous() {
		let hay = [0xA1, 0x00, 0xA1, 0x00];
		let sig = parse_mask("A1 00");
		assert_eq!(unique_match(&hay, &sig, "t"), Err(Error::Ambiguous("t")));
	}

	#[test]
	fn unique_match_rejects_missing() {
		let hay = [0x00, 0x01, 0x02];
		let sig = parse_mask("A1 A1");
		assert_eq!(unique_match(&hay, &sig, "t"), Err(Error::NotFound("t")));
	}

	#[test]
	fn offset_by_call_follows_rel32_without_dereferencing() {
		// at 0x400010: `call +0x20` -> 0x400015 + 0x20 = 0x400035
		let bytes: &'static [u8] = Box::leak(Box::new([
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0xE8, 0x20, 0x00, 0x00, 0x00, 0x90,
		]));
		let module = Module::from_parts(0, 0x400000, bytes);
		let sig = Signature::new(SignatureTreatment::OffsetByCall, "E8 20 00 00 00 90");
		assert_eq!(sig.find(&module, "t"), Ok(0x400035));
	}

	#[test]
	fn offset_by_call_rejects_a_truncated_rel32() {
		let bytes: &'static [u8] = Box::leak(Box::new([0x00, 0xE8, 0x01, 0x02]));
		let module = Module::from_parts(0, 0x400000, bytes);
		let sig = Signature::new(SignatureTreatment::OffsetByCall, "E8");
		assert_eq!(sig.find(&module, "t"), Err(Error::NotFound("t")));
	}

	#[test]
	fn offset_by_int_reads_the_operand_out_of_the_slice() {
		// `A1 EC B2 42 00` = mov eax, [0x42B2EC]
		let bytes: &'static [u8] = Box::leak(Box::new([0x90, 0xA1, 0xEC, 0xB2, 0x42, 0x00, 0x90]));
		let module = Module::from_parts(0, 0x500000, bytes);
		let sig = Signature::new(SignatureTreatment::OffsetByInt(1), "A1 ?? ?? ?? ?? 90");
		assert_eq!(sig.find(&module, "t"), Ok(0x42B2EC));
	}
}
