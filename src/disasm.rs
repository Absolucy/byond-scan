// SPDX-License-Identifier: MPL-2.0
//! pulling an address or an offset out of an instruction, and following
//! calls. iced-x86 does the actual instruction reading.

use crate::{
	decode::{absolute_displacement, function_instructions, register_displacement},
	error::{Error, Result},
	module::Module,
};
pub use iced_x86::Register;
use iced_x86::{Instruction, Mnemonic, OpKind};

/// which instruction to read a fixed memory address (like `[0x42B2EC]`) from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperandSelect {
	/// the first one.
	FirstAbsMem,
	/// the nth one, counting from 0.
	NthAbsMem(usize),
	/// the first one after a `cmp` against this constant.
	AfterTagCompare(u32),
}

/// which instruction to read a field offset (the `0x0C` in `[ecx+0x0C]`)
/// from. `base` is the register it has to go through, `ecx` in that example.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegMemDispSelect {
	First {
		base: Register,
	},
	/// the nth one that goes through `base`, counting from 0.
	Nth {
		base: Register,
		index: usize,
	},
}

/// reads instructions starting at `fn_ptr` and returns the fixed memory
/// address that `select` picks.
pub fn abs_mem_operand(
	module: &Module,
	fn_ptr: usize,
	select: OperandSelect,
	name: &'static str,
) -> Result<usize> {
	let instructions = function_instructions(module, fn_ptr).ok_or(Error::NotFound(name))?;
	let mut armed = !matches!(select, OperandSelect::AfterTagCompare(_));
	let mut nth = 0usize;

	for insn in instructions {
		if let OperandSelect::AfterTagCompare(tag) = select
			&& insn.mnemonic() == Mnemonic::Cmp
			&& has_immediate(&insn, u64::from(tag))
		{
			armed = true;
			continue;
		}
		if !armed {
			continue;
		}

		if let Some(disp) = absolute_displacement(&insn) {
			match select {
				OperandSelect::FirstAbsMem | OperandSelect::AfterTagCompare(_) => return Ok(disp),
				OperandSelect::NthAbsMem(target) => {
					if nth == target {
						return Ok(disp);
					}
					nth += 1;
				}
			}
		}
	}
	Err(Error::DecodeExhausted(name))
}

/// reads instructions starting at `fn_ptr` and returns the field offset
/// that `select` picks.
pub fn reg_mem_disp_operand(
	module: &Module,
	fn_ptr: usize,
	select: RegMemDispSelect,
	name: &'static str,
) -> Result<usize> {
	reg_mem_disp_operand_inner(module, fn_ptr, select, name, None)
}

/// same as [`reg_mem_disp_operand`], but only starts counting after an
/// instruction that touches the fixed address `after_abs_mem`.
pub fn reg_mem_disp_after_abs_mem(
	module: &Module,
	fn_ptr: usize,
	after_abs_mem: usize,
	select: RegMemDispSelect,
	name: &'static str,
) -> Result<usize> {
	reg_mem_disp_operand_inner(module, fn_ptr, select, name, Some(after_abs_mem))
}

/// returns where the nth direct `call` goes, counting from 0.
pub fn follow_call(
	module: &Module,
	fn_ptr: usize,
	nth: usize,
	name: &'static str,
) -> Result<usize> {
	let instructions = function_instructions(module, fn_ptr).ok_or(Error::NotFound(name))?;
	let mut seen = 0usize;

	for insn in instructions {
		if insn.mnemonic() == Mnemonic::Call && insn.op0_kind() == OpKind::NearBranch32 {
			if seen == nth {
				return Ok(insn.near_branch32() as usize);
			}
			seen += 1;
		}
	}
	Err(Error::DecodeExhausted(name))
}

fn reg_mem_disp_operand_inner(
	module: &Module,
	fn_ptr: usize,
	select: RegMemDispSelect,
	name: &'static str,
	after_abs_mem: Option<usize>,
) -> Result<usize> {
	let instructions = function_instructions(module, fn_ptr).ok_or(Error::NotFound(name))?;
	let mut armed = after_abs_mem.is_none();
	let mut nth = 0usize;

	for insn in instructions {
		if !armed {
			if absolute_displacement(&insn) == after_abs_mem {
				armed = true;
			}
			continue;
		}

		if let Some(disp) = register_displacement(&insn, select.base()) {
			match select {
				RegMemDispSelect::First { .. } => return Ok(disp),
				RegMemDispSelect::Nth { index, .. } => {
					if nth == index {
						return Ok(disp);
					}
					nth += 1;
				}
			}
		}
	}
	Err(Error::DecodeExhausted(name))
}

impl RegMemDispSelect {
	fn base(self) -> Register {
		match self {
			Self::First { base } | Self::Nth { base, .. } => base,
		}
	}
}

fn has_immediate(insn: &Instruction, value: u64) -> bool {
	(0..insn.op_count()).any(|i| is_immediate(insn.op_kind(i)) && insn.immediate(i) == value)
}

fn is_immediate(kind: OpKind) -> bool {
	matches!(
		kind,
		OpKind::Immediate8
			| OpKind::Immediate8_2nd
			| OpKind::Immediate16
			| OpKind::Immediate32
			| OpKind::Immediate64
			| OpKind::Immediate8to16
			| OpKind::Immediate8to32
			| OpKind::Immediate8to64
			| OpKind::Immediate32to64
	)
}

#[cfg(test)]
mod tests {
	use super::{
		OperandSelect, RegMemDispSelect, Register, abs_mem_operand, follow_call,
		reg_mem_disp_operand,
	};
	use crate::{Error, Module};

	fn module(bytes: &[u8]) -> Module {
		Module::from_parts(0, 0x1000, Box::leak(bytes.into()))
	}

	const FIRST_EBX: RegMemDispSelect = RegMemDispSelect::First {
		base: Register::EBX,
	};

	#[test]
	fn nothing_is_read_out_of_the_function_next_door() {
		// ret, and then a whole other function:
		// call $+5; mov eax,[0x4000]; mov eax,[ebx+0x64]; ret
		let after_ret = module(&[
			0xC3, 0xE8, 0x00, 0x00, 0x00, 0x00, 0xA1, 0x00, 0x40, 0x00, 0x00, 0x8B, 0x43, 0x64,
			0xC3,
		]);
		// jmp 0 (a tail call), the int3 MSVC pads with, and the same neighbor
		let after_tail_call = module(&[
			0xE9, 0xFB, 0xEF, 0xFF, 0xFF, 0xCC, 0xE8, 0x00, 0x00, 0x00, 0x00, 0xA1, 0x00, 0x40,
			0x00, 0x00, 0x8B, 0x43, 0x64, 0xC3,
		]);
		for module in [after_ret, after_tail_call] {
			assert_eq!(
				follow_call(&module, 0x1000, 0, "t"),
				Err(Error::DecodeExhausted("t"))
			);
			assert_eq!(
				abs_mem_operand(&module, 0x1000, OperandSelect::FirstAbsMem, "t"),
				Err(Error::DecodeExhausted("t"))
			);
			assert_eq!(
				reg_mem_disp_operand(&module, 0x1000, FIRST_EBX, "t"),
				Err(Error::DecodeExhausted("t"))
			);
		}
	}

	#[test]
	fn an_early_return_does_not_end_the_function() {
		// je +1; ret; mov eax,[0x4000]; call $+5; mov eax,[ebx+0x64]; ret
		let module = module(&[
			0x74, 0x01, 0xC3, 0xA1, 0x00, 0x40, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x8B,
			0x43, 0x64, 0xC3,
		]);
		assert_eq!(follow_call(&module, 0x1000, 0, "t"), Ok(0x100D));
		assert_eq!(
			abs_mem_operand(&module, 0x1000, OperandSelect::FirstAbsMem, "t"),
			Ok(0x4000)
		);
		assert_eq!(
			reg_mem_disp_operand(&module, 0x1000, FIRST_EBX, "t"),
			Ok(0x64)
		);
	}

	#[test]
	fn calls_are_counted_across_the_jmp_that_ends_a_switch_case() {
		// call $+5; jmp 0; call $+5; ret
		let module = module(&[
			0xE8, 0x00, 0x00, 0x00, 0x00, 0xE9, 0xF6, 0xEF, 0xFF, 0xFF, 0xE8, 0x00, 0x00, 0x00,
			0x00, 0xC3,
		]);
		assert_eq!(follow_call(&module, 0x1000, 1, "t"), Ok(0x100F));
	}
}
