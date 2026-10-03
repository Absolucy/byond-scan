// SPDX-License-Identifier: MPL-2.0
//! sanity checks for a recipe that's being tried on a build nobody verified
//! it on.

use crate::{
	AddressRange, Module,
	decode::{
		absolute_displacement, any_register_displacement, decoder_for_range, function_instructions,
		register_displacement,
	},
};
use iced_x86::{Instruction, MemorySize, Mnemonic, Register};

#[must_use]
pub fn is_aligned_writable(module: &Module, address: usize) -> bool {
	address.is_multiple_of(4) && module.is_writable(address)
}

/// counts the instructions that touch the fixed address `target`, optionally
/// skipping one range.
///
/// this reads the code one instruction at a time on purpose. just searching
/// the bytes would also count random spots that happen to spell the address.
#[must_use]
pub fn absolute_reference_count(
	module: &Module,
	target: usize,
	exclude: Option<AddressRange>,
) -> usize {
	module
		.executable_ranges()
		.iter()
		.filter_map(|range| decoder_for_range(module, *range))
		.map(|mut decoder| {
			let mut count = 0;
			let mut instruction = Instruction::default();
			while decoder.can_decode() {
				decoder.decode_out(&mut instruction);
				if exclude.is_some_and(|range| range.contains(instruction.ip() as usize)) {
					continue;
				}
				if absolute_displacement(&instruction) == Some(target) {
					count += 1;
				}
			}
			count
		})
		.sum()
}

#[must_use]
pub fn has_independent_absolute_reference(
	module: &Module,
	target: usize,
	extraction_address: usize,
) -> bool {
	let excluded = AddressRange::new(extraction_address, 0x200);
	absolute_reference_count(module, target, Some(excluded)) != 0
}

#[must_use]
pub fn function_references_absolute(module: &Module, start: usize, target: usize) -> bool {
	function_instructions(module, start).is_some_and(|mut instructions| {
		instructions.any(|instruction| absolute_displacement(&instruction) == Some(target))
	})
}

/// does this function read or write a whole 8-byte BYOND value at
/// `[base + displacement]`? GCC does it with one `movq`, MSVC with two 4-byte
/// accesses side by side. either counts.
#[must_use]
pub fn function_has_value_access(
	module: &Module,
	start: usize,
	base: Register,
	displacement: usize,
) -> bool {
	let Some(instructions) = function_instructions(module, start) else {
		return false;
	};
	let mut low = false;
	let mut high = false;
	for instruction in instructions {
		if register_displacement(&instruction, base) == Some(displacement)
			&& instruction.mnemonic() == Mnemonic::Movq
		{
			return true;
		}
		// each half has to be a real 4-byte access. `lea` only names the
		// address, and a 1-byte load is the type tag by itself
		let dword = matches!(
			instruction.memory_size(),
			MemorySize::UInt32 | MemorySize::Int32
		);
		match register_displacement(&instruction, base) {
			Some(value) if dword && value == displacement => low = true,
			Some(value) if dword && value == displacement + 4 => high = true,
			_ => {}
		}
		if low && high {
			return true;
		}
	}
	false
}

#[must_use]
pub fn register_displacement_reference_count(module: &Module, displacement: usize) -> usize {
	module
		.executable_ranges()
		.iter()
		.filter_map(|range| decoder_for_range(module, *range))
		.map(|mut decoder| {
			let mut count = 0;
			let mut instruction = Instruction::default();
			while decoder.can_decode() {
				decoder.decode_out(&mut instruction);
				if any_register_displacement(&instruction) == Some(displacement) {
					count += 1;
				}
			}
			count
		})
		.sum()
}

#[cfg(test)]
mod tests {
	use super::{
		absolute_reference_count, function_has_value_access, function_references_absolute,
		has_independent_absolute_reference, is_aligned_writable,
	};
	use crate::{AddressRange, Module};
	use iced_x86::Register;

	fn module(bytes: Vec<u8>) -> Module {
		let bytes = Box::leak(bytes.into_boxed_slice());
		let executable = Box::leak(vec![AddressRange::new(0x1000, bytes.len())].into_boxed_slice());
		let writable = Box::leak(vec![AddressRange::new(0x4000, 0x100)].into_boxed_slice());
		Module::from_parts_with_ranges(0, 0x1000, bytes, executable, writable)
	}

	#[test]
	fn validates_regions_and_independent_absolute_references() {
		// mov eax,[0x4000]; 0x200 nops; mov ecx,[0x4000]
		let mut bytes = vec![0xA1, 0x00, 0x40, 0x00, 0x00];
		bytes.extend(std::iter::repeat_n(0x90, 0x200));
		bytes.extend([0x8B, 0x0D, 0x00, 0x40, 0x00, 0x00]);
		let module = module(bytes);

		assert!(is_aligned_writable(&module, 0x4000));
		assert!(!is_aligned_writable(&module, 0x4002));
		assert_eq!(absolute_reference_count(&module, 0x4000, None), 2);
		assert!(function_references_absolute(&module, 0x1000, 0x4000));
		assert!(has_independent_absolute_reference(&module, 0x4000, 0x1000));
	}

	#[test]
	fn recognizes_paired_value_accesses() {
		// mov eax,[ebx+0x64]; mov ecx,[ebx+0x68]
		let module = module(vec![0x8B, 0x43, 0x64, 0x8B, 0x4B, 0x68, 0xC3]);
		assert!(function_has_value_access(
			&module,
			0x1000,
			Register::EBX,
			0x64
		));
	}

	#[test]
	fn the_function_next_door_does_not_count() {
		// ret, and then: mov eax,[0x4000]; mov eax,[ebx+0x64]; mov
		// ecx,[ebx+0x68]; ret
		let module = module(vec![
			0xC3, 0xA1, 0x00, 0x40, 0x00, 0x00, 0x8B, 0x43, 0x64, 0x8B, 0x4B, 0x68, 0xC3,
		]);
		assert!(!function_references_absolute(&module, 0x1000, 0x4000));
		assert!(!function_has_value_access(
			&module,
			0x1000,
			Register::EBX,
			0x64
		));
	}

	#[test]
	fn byte_loads_and_address_math_are_not_a_value_access() {
		// mov al,[ebx+0x64]; mov cl,[ebx+0x68]
		let byte_loads = module(vec![0x8A, 0x43, 0x64, 0x8A, 0x4B, 0x68, 0xC3]);
		assert!(!function_has_value_access(
			&byte_loads,
			0x1000,
			Register::EBX,
			0x64
		));
		// lea eax,[ebx+0x64]; lea ecx,[ebx+0x68]
		let address_math = module(vec![0x8D, 0x43, 0x64, 0x8D, 0x4B, 0x68, 0xC3]);
		assert!(!function_has_value_access(
			&address_math,
			0x1000,
			Register::EBX,
			0x64
		));
	}
}
