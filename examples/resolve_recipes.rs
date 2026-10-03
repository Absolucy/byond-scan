// SPDX-License-Identifier: MPL-2.0
//! Resolves a chained recipe list against a tiny hand-assembled module.
//!
//! ```text
//! cargo run --example resolve_recipes
//! ```
//!
//! No BYOND needed. The fake module is three functions, laid out the way a
//! real one tends to be: an accessor that reads a global, a wrapper that calls
//! a helper, and the helper itself.

use byond_scan::{
	AddressRange, Anchor, Extract, Module, OperandSelect, Recipe, RegMemDispSelect, Register,
	SignatureTreatment, VersionRange, resolve_recipe,
};
use std::collections::HashMap;

const CODE_START: usize = 0x1000;

#[rustfmt::skip]
static CODE: [u8; 28] = [
	// 0x1000 get_thing_table:
	0xA1, 0x00, 0x40, 0x00, 0x00,       // mov eax, [0x4000]
	0xC3,                               // ret
	0xCC, 0xCC,
	// 0x1008 lookup_thing_wrapper:
	0x55,                               // push ebp
	0x8B, 0xEC,                         // mov ebp, esp
	0xE8, 0x08, 0x00, 0x00, 0x00,       // call 0x1018
	0x5D,                               // pop ebp
	0xC3,                               // ret
	0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
	// 0x1018 lookup_thing:
	0x8B, 0x41, 0x0C,                   // mov eax, [ecx+0x0C]
	0xC3,                               // ret
];

static EXECUTABLE: [AddressRange; 1] = [AddressRange::new(CODE_START, CODE.len())];
static WRITABLE: [AddressRange; 1] = [AddressRange::new(0x4000, 0x100)];

// order matters: an `Anchor::From` can only name a recipe above it
const RECIPES: &[Recipe] = &[
	// a function, recognized by its own bytes. the global's address is
	// wildcarded because it moves between builds
	Recipe {
		name: "get_thing_table",
		versions: VersionRange::ALL,
		anchor: Anchor::Signature(SignatureTreatment::NoOffset, "A1 ?? ?? ?? ?? C3"),
		hops: &[],
		extract: Extract::Entry,
	},
	// the global that function reads. zeroed data has no bytes to match, so
	// it is found through the instruction that refers to it
	Recipe {
		name: "thing_table",
		versions: VersionRange::ALL,
		anchor: Anchor::From("get_thing_table"),
		hops: &[],
		extract: Extract::AbsMem(OperandSelect::FirstAbsMem),
	},
	// a neighbor of that global at a known distance
	Recipe {
		name: "thing_count",
		versions: VersionRange::ALL,
		anchor: Anchor::From("thing_table"),
		hops: &[],
		extract: Extract::Offset(4),
	},
	// a function with nothing distinctive of its own, reached by matching its
	// caller and following the caller's first call
	Recipe {
		name: "lookup_thing",
		versions: VersionRange::ALL,
		anchor: Anchor::Signature(
			SignatureTreatment::NoOffset,
			"55 8B EC E8 ?? ?? ?? ?? 5D C3",
		),
		hops: &[0],
		extract: Extract::Entry,
	},
	// a struct field offset, read out of the code that uses it
	Recipe {
		name: "thing_name_offset",
		versions: VersionRange::ALL,
		anchor: Anchor::From("lookup_thing"),
		hops: &[],
		extract: Extract::RegMemDisp(RegMemDispSelect::First {
			base: Register::ECX,
		}),
	},
];

fn main() -> byond_scan::Result<()> {
	// base 0 keeps every result a link-time address. a live module comes from
	// `Module::current()` instead
	let module = Module::from_parts_with_ranges(0, CODE_START, &CODE, &EXECUTABLE, &WRITABLE);

	let mut resolved: HashMap<&str, usize> = HashMap::with_capacity(RECIPES.len());
	for recipe in RECIPES {
		let value = resolve_recipe(&module, recipe, |name| resolved.get(name).copied())?;
		println!("{:<18} {value:#x}", recipe.name);
		resolved.insert(recipe.name, value);
	}

	assert_eq!(resolved["get_thing_table"], 0x1000);
	assert_eq!(resolved["thing_table"], 0x4000);
	assert_eq!(resolved["thing_count"], 0x4004);
	assert_eq!(resolved["lookup_thing"], 0x1018);
	assert_eq!(resolved["thing_name_offset"], 0x0C);
	assert!(module.is_executable(resolved["lookup_thing"]));
	assert!(module.is_writable(resolved["thing_table"]));
	Ok(())
}
