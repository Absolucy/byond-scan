// SPDX-License-Identifier: MPL-2.0
use crate::{AddressRange, Module};
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};

/// how many instructions to read before giving up. generous, because some
/// functions bury what we want deep inside. it still has to be a limit, so a
/// bad starting address can't keep reading forever.
const MAX_FUNCTION_INSTRUCTIONS: usize = 512;

/// the instructions of the function at `start`, in address order, up to where
/// the function ends.
///
/// the end is the first `ret` (or `int3` padding) that no earlier branch jumps
/// past. an early return in the middle of a function has a branch going over
/// it, so reading carries on there. without this, a scan that doesn't find
/// what it wants walks straight into the function next door and answers from
/// that.
///
/// a `jmp` is not an end, on purpose. recipes anchor inside one `switch` case
/// and count calls across the cases after it, and every case ends in a `jmp`.
/// the price: a function that ends in a tail-call `jmp` can still get read
/// past. MSVC's `int3` padding only stops it when the `jmp` goes backward.
///
/// it only sees branches from `start` onward. hand it an address in the middle
/// of a function and it can stop short, which fails loudly.
pub(crate) fn function_instructions(
	module: &Module,
	start: usize,
) -> Option<impl Iterator<Item = Instruction>> {
	let mut decoder = decoder_at(module, start)?;
	let mut furthest_branch = 0;
	let mut ended = false;
	let instructions = std::iter::from_fn(move || {
		if ended || !decoder.can_decode() {
			return None;
		}
		let instruction = decoder.decode();
		if instruction.op0_kind() == OpKind::NearBranch32
			&& instruction.mnemonic() != Mnemonic::Call
		{
			furthest_branch = furthest_branch.max(instruction.near_branch_target());
		}
		// iced's own `flow_control()` needs the `instr_info` feature, which
		// would drag its big tables into the cdylib
		let leaves = matches!(
			instruction.mnemonic(),
			Mnemonic::Ret | Mnemonic::Retf | Mnemonic::Int3
		);
		ended = leaves && furthest_branch < decoder.ip();
		Some(instruction)
	});
	Some(instructions.take(MAX_FUNCTION_INSTRUCTIONS))
}

pub(crate) fn decoder_at(module: &Module, address: usize) -> Option<Decoder<'static>> {
	let offset = address.checked_sub(module.range_start())?;
	let code = module.range().get(offset..)?;
	if code.is_empty() {
		return None;
	}
	Some(Decoder::with_ip(
		32,
		code,
		address as u64,
		DecoderOptions::NONE,
	))
}

pub(crate) fn decoder_for_range(module: &Module, range: AddressRange) -> Option<Decoder<'static>> {
	if range.is_empty() {
		return None;
	}
	let offset = range.start.checked_sub(module.range_start())?;
	let available = module.range().get(offset..)?;
	let code = available.get(..range.len().min(available.len()))?;
	if code.is_empty() {
		return None;
	}
	Some(Decoder::with_ip(
		32,
		code,
		range.start as u64,
		DecoderOptions::NONE,
	))
}

pub(crate) fn absolute_displacement(instruction: &Instruction) -> Option<usize> {
	if !has_memory_operand(instruction) || instruction.memory_base() != Register::None {
		return None;
	}
	Some(instruction.memory_displacement32() as usize)
}

pub(crate) fn register_displacement(instruction: &Instruction, base: Register) -> Option<usize> {
	if !has_memory_operand(instruction) || instruction.memory_base() != base {
		return None;
	}
	Some(instruction.memory_displacement32() as usize)
}

pub(crate) fn any_register_displacement(instruction: &Instruction) -> Option<usize> {
	if !has_memory_operand(instruction) || instruction.memory_base() == Register::None {
		return None;
	}
	Some(instruction.memory_displacement32() as usize)
}

fn has_memory_operand(instruction: &Instruction) -> bool {
	(0..instruction.op_count()).any(|index| instruction.op_kind(index) == OpKind::Memory)
}

#[cfg(test)]
mod tests {
	use super::{absolute_displacement, decoder_at, register_displacement};
	use crate::Module;
	use iced_x86::Register;

	fn module() -> Module {
		let bytes = Box::leak(vec![0x90, 0xA1, 0x00, 0x40, 0x00, 0x00].into_boxed_slice());
		Module::from_parts(0, 0x1000, bytes)
	}

	#[test]
	fn decoder_uses_strict_half_open_module_bounds() {
		let module = module();

		assert!(decoder_at(&module, 0x0FFF).is_none());
		assert!(decoder_at(&module, 0x1000).is_some());
		assert!(decoder_at(&module, 0x1005).is_some());
		assert!(decoder_at(&module, 0x1006).is_none());
		assert!(decoder_at(&module, 0x1007).is_none());
	}

	#[test]
	fn classifies_absolute_and_register_memory_displacements() {
		let absolute_module = module();
		let mut absolute_decoder = decoder_at(&absolute_module, 0x1001).unwrap();
		let absolute = absolute_decoder.decode();
		assert_eq!(absolute_displacement(&absolute), Some(0x4000));
		assert_eq!(register_displacement(&absolute, Register::EAX), None);

		let bytes = Box::leak(vec![0x8B, 0x43, 0x64].into_boxed_slice());
		let register_module = Module::from_parts(0, 0x2000, bytes);
		let mut register_decoder = decoder_at(&register_module, 0x2000).unwrap();
		let register = register_decoder.decode();
		assert_eq!(absolute_displacement(&register), None);
		assert_eq!(register_displacement(&register, Register::EBX), Some(0x64));
	}
}
