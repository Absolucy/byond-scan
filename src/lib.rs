// SPDX-License-Identifier: MPL-2.0
//! finds BYOND functions and globals inside a loaded `byondcore.dll` or
//! `libbyond.so`.
//!
//! BYOND's globals start out as zeros, so there's nothing to match on. they
//! get found through the instructions that use them instead. anything read
//! out of a live instruction is already a real address on both platforms -
//! only an offset you pinned by hand needs `module.base() + offset`.
//!
//! there are no recipes in here, just the scanner. `README.md` covers how a
//! recipe works and how to write one.

mod decode;
pub mod disasm;
pub mod error;
pub mod module;
mod platform;
pub mod recipe;
pub mod signature;
pub mod validation;
pub mod version;

pub use disasm::{OperandSelect, RegMemDispSelect, Register};
pub use error::{Error, Result};
pub use module::{AddressRange, MODULE_NAME, Module};
/// looks up a BYOND export by name. for the handful of functions that are
/// exported and so need no byte pattern at all - byondapi's are.
pub use platform::find_export;
pub use recipe::{
	Anchor, Extract, Recipe, RecipeApplicability, ResolvedRecipe, VersionRange, defines,
	names_contain, resolve_recipe, resolve_recipe_with_trace,
};
pub use signature::{Signature, SignatureTreatment, parse_mask};
pub use version::version;

// compiles the README's snippets, so an API rename breaks the build and not
// the docs
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
