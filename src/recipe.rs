// SPDX-License-Identifier: MPL-2.0
//! recipes: a description of where something is, as plain data.
//!
//! an [`Anchor`] finds some code, the hops follow calls out of it, and an
//! [`Extract`] reads the address or offset you were after.

use crate::{
	disasm::{self, OperandSelect, RegMemDispSelect},
	error::{Error, Result},
	module::Module,
	signature::{Signature, SignatureTreatment},
};
use std::ffi::CStr;

/// the builds a recipe was actually checked on. both ends are included.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VersionRange {
	pub min: u32,
	pub max: u32,
}

impl VersionRange {
	/// every build.
	pub const ALL: Self = Self {
		min: 0,
		max: u32::MAX,
	};

	#[must_use]
	pub const fn only(build: u32) -> Self {
		Self {
			min: build,
			max: build,
		}
	}

	#[must_use]
	pub const fn from(min: u32) -> Self {
		Self { min, max: u32::MAX }
	}

	#[must_use]
	pub fn contains(&self, build: u32) -> bool {
		self.min <= build && build <= self.max
	}

	/// says how far to trust this recipe on the running build.
	///
	/// in range is [`RecipeApplicability::Verified`]. newer than the range is
	/// [`RecipeApplicability::ForwardCandidate`]. older, or a different major
	/// version than `supported_version`, is `None`.
	#[must_use]
	pub fn applicability(
		&self,
		version: u32,
		build: u32,
		supported_version: u32,
	) -> Option<RecipeApplicability> {
		if version != supported_version {
			return None;
		}
		if self.contains(build) {
			return Some(RecipeApplicability::Verified);
		}
		if build > self.max && self.max != u32::MAX {
			return Some(RecipeApplicability::ForwardCandidate);
		}
		None
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecipeApplicability {
	/// the build is inside the range somebody checked.
	Verified,
	/// the build is newer than anything checked. it might still work, but
	/// validate the result before you trust it.
	ForwardCandidate,
}

/// where a recipe starts looking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Anchor {
	/// an exported function, by name. like `Byond_GetVersion`.
	Export(&'static CStr),
	/// wherever this byte pattern matches. the treatment says what to do
	/// with the match.
	Signature(SignatureTreatment, &'static str),
	/// the result of an earlier recipe. that recipe has to come first in
	/// your list.
	From(&'static str),
}

/// what to read once the recipe has found its code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Extract {
	/// the address itself. for functions.
	Entry,
	/// a fixed memory address an instruction touches. for globals.
	AbsMem(OperandSelect),
	/// the `0x0C` in something like `[ecx+0x0C]`. for struct fields.
	RegMemDisp(RegMemDispSelect),
	/// same as `RegMemDisp`, but only counting instructions after the one
	/// that touches the global named `after`.
	RegMemDispAfterAbsMem {
		after: &'static str,
		select: RegMemDispSelect,
	},
	/// the address plus a fixed number of bytes. this one goes wrong
	/// quietly if the layout shifts, so check it on every build in the range.
	Offset(isize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Recipe {
	pub name: &'static str,
	pub versions: VersionRange,
	pub anchor: Anchor,
	/// calls to follow before extracting, in order, counting from 0.
	/// `&[0, 2]` goes into the first call, then into that function's third.
	pub hops: &'static [usize],
	pub extract: Extract,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedRecipe {
	pub value: usize,
	/// where the extract step read from, after any hops.
	pub extraction_address: usize,
}

// `str` has no const `==`, so compare bytes by hand
const fn str_eq(a: &str, b: &str) -> bool {
	let (a, b) = (a.as_bytes(), b.as_bytes());
	if a.len() != b.len() {
		return false;
	}
	let mut i = 0;
	while i < a.len() {
		if a[i] != b[i] {
			return false;
		}
		i += 1;
	}
	true
}

/// is there a recipe called `name` in this list? it's a `const fn`, so you
/// can `assert!` on it at compile time.
#[must_use]
pub const fn defines(recipes: &[Recipe], name: &str) -> bool {
	let mut i = 0;
	while i < recipes.len() {
		if str_eq(recipes[i].name, name) {
			return true;
		}
		i += 1;
	}
	false
}

/// same idea as [`defines`], for a plain list of names.
#[must_use]
pub const fn names_contain(names: &[&str], name: &str) -> bool {
	let mut i = 0;
	while i < names.len() {
		if str_eq(names[i], name) {
			return true;
		}
		i += 1;
	}
	false
}

/// runs one recipe. `resolved` is how it looks up the earlier results that
/// [`Anchor::From`] names.
pub fn resolve_recipe(
	module: &Module,
	recipe: &Recipe,
	resolved: impl Fn(&str) -> Option<usize>,
) -> Result<usize> {
	resolve_recipe_with_trace(module, recipe, resolved).map(|result| result.value)
}

/// same as [`resolve_recipe`], but also tells you where it read the answer
/// from.
pub fn resolve_recipe_with_trace(
	module: &Module,
	recipe: &Recipe,
	resolved: impl Fn(&str) -> Option<usize>,
) -> Result<ResolvedRecipe> {
	let mut addr = match &recipe.anchor {
		// offline modules must use their attached exports, not the host loader
		Anchor::Export(sym) => module
			.find_export(sym)
			.ok_or(Error::ExportNotFound(recipe.name))?,
		Anchor::Signature(treatment, mask) => {
			Signature::new(*treatment, mask).find(module, recipe.name)?
		}
		Anchor::From(dep) => resolved(dep).ok_or(Error::NotFound(recipe.name))?,
	};

	for &nth in recipe.hops {
		addr = disasm::follow_call(module, addr, nth, recipe.name)?;
	}

	let value = match recipe.extract {
		Extract::Entry => Ok(addr),
		Extract::AbsMem(select) => disasm::abs_mem_operand(module, addr, select, recipe.name),
		Extract::RegMemDisp(select) => {
			disasm::reg_mem_disp_operand(module, addr, select, recipe.name)
		}
		Extract::RegMemDispAfterAbsMem { after, select } => {
			let after_abs_mem = resolved(after).ok_or(Error::NotFound(recipe.name))?;
			disasm::reg_mem_disp_after_abs_mem(module, addr, after_abs_mem, select, recipe.name)
		}
		Extract::Offset(delta) => Ok((addr as isize + delta) as usize),
	}?;
	Ok(ResolvedRecipe {
		value,
		extraction_address: addr,
	})
}

#[cfg(test)]
mod tests {
	use super::{RecipeApplicability, VersionRange};

	#[test]
	fn applicability_distinguishes_verified_and_forward_builds() {
		let range = VersionRange {
			min: 1669,
			max: 1685,
		};
		assert_eq!(
			range.applicability(516, 1685, 516),
			Some(RecipeApplicability::Verified)
		);
		assert_eq!(
			range.applicability(516, 1686, 516),
			Some(RecipeApplicability::ForwardCandidate)
		);
		assert_eq!(range.applicability(516, 1668, 516), None);
		assert_eq!(range.applicability(517, 1686, 516), None);
	}

	#[test]
	fn all_range_never_becomes_a_forward_candidate() {
		assert_eq!(
			VersionRange::ALL.applicability(516, u32::MAX, 516),
			Some(RecipeApplicability::Verified)
		);
	}
}
