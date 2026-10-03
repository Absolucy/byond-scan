# byond-scan

## disclaimer

this crate was made by coding LLMs.

use at your own volition, i make no claims that this is production-ready or perfect or whatever. it works for me, but your experiences may vary.

~Absolucy

## wtf this does

finds functions, globals, and struct field offsets inside BYOND's
`byondcore.dll` / `libbyond.so`, so you don't have to hardcode an address that
dies the moment a new build drops.

you write a **recipe**: a byte pattern that finds some code, plus which part of
that code holds the thing you want. the scanner matches the pattern, reads the
instructions it lands on, and gives you the address.

a few things up front:

- **there are no recipes in here.** this is just the scanner. the patterns for
  actual BYOND builds are yours to write.
- **32-bit only**, because BYOND is. build for `i686-pc-windows-msvc` or
  `i686-unknown-linux-gnu`.
- **it won't guess.** a pattern that matches zero times, or more than once, is
  an error.

## using it

```toml
[dependencies]
byond-scan = { git = "https://github.com/Absolucy/byond-scan" }
```

then, from inside a library BYOND has loaded:

```rust,no_run
use byond_scan::{
	Anchor, Extract, Module, OperandSelect, Recipe, SignatureTreatment, VersionRange,
	resolve_recipe,
};
use std::collections::HashMap;

// made-up patterns, just to show the shape
const RECIPES: &[Recipe] = &[
	// a function, found by its own bytes
	Recipe {
		name: "get_thing_table",
		versions: VersionRange { min: 1659, max: 1688 },
		anchor: Anchor::Signature(SignatureTreatment::NoOffset, "A1 ?? ?? ?? ?? C3"),
		hops: &[],
		extract: Extract::Entry,
	},
	// the global that function reads
	Recipe {
		name: "thing_table",
		versions: VersionRange { min: 1659, max: 1688 },
		anchor: Anchor::From("get_thing_table"),
		hops: &[],
		extract: Extract::AbsMem(OperandSelect::FirstAbsMem),
	},
];

fn resolve_all() -> byond_scan::Result<HashMap<&'static str, usize>> {
	let module = Module::current()?;
	let mut resolved = HashMap::with_capacity(RECIPES.len());
	for recipe in RECIPES {
		let address = resolve_recipe(&module, recipe, |name| resolved.get(name).copied())?;
		resolved.insert(recipe.name, address);
	}
	Ok(resolved)
}
```

order matters: `thing_table` starts from `get_thing_table`'s result, so it has
to come after it.

want to poke at it without BYOND? this runs the same loop against a tiny fake
module:

```text
cargo run --example resolve_recipes
```

## what's in a recipe

three steps, in order.

**1. `anchor`: where to start.**

| `Anchor` | starts at |
|---|---|
| `Signature(treatment, mask)` | wherever the byte mask matches |
| `Export(name)` | an exported symbol, like a `Byond_*` function |
| `From(name)` | the result of an earlier recipe |

a mask is hex bytes with `??` for "anything":
`"55 8B EC E8 ?? ?? ?? ?? 5D C3"`. wildcard whatever changes between builds,
which is mostly addresses and call distances.

the treatment says what to do with the match:

| `SignatureTreatment` | gives you |
|---|---|
| `NoOffset` | the address of the match |
| `OffsetByInt(n)` | the 32-bit value sitting `n` bytes into the match |
| `OffsetByCall` | the function that the `call` at the match calls |
| `RewindTo { mask, window }` | an earlier spot, found by a second mask within `window` bytes before the match. for functions that only look distinctive near the end |

**2. `hops`: calls to follow.** `&[0, 2]` means "go into the first function
this calls, then into the third one *that* calls". empty means stay put.

**3. `extract`: what to read.**

| `Extract` | gives you | use it for |
|---|---|---|
| `Entry` | the address itself | functions |
| `AbsMem(select)` | a fixed memory address an instruction touches | globals |
| `RegMemDisp(select)` | the `0x0C` in `mov eax, [ecx+0x0C]` | struct fields |
| `RegMemDispAfterAbsMem { after, select }` | same, but only counting instructions after the one that touches the global named `after` | struct fields |
| `Offset(n)` | the address plus `n` bytes | a neighbor at a known distance |

`select` picks which matching instruction: the first, the nth, or (for globals)
the first one after a compare against some constant.

hops and extracts read forward from where they start until the function ends,
which is the first `ret` that no earlier branch jumps over. if what you asked
for isn't there, you get `DecodeExhausted`, not something from the function
next door. a `jmp` doesn't count as an end. that's what lets you anchor inside
one `switch` case and count through the cases after it, but it also means a
function that ends in a `jmp` can still be read past.

why do globals go through code? because BYOND's globals start out as zeros, so
there's nothing to match on. you find a function that *uses* the global and
read the address out of it.

## which recipes fail quietly

this is the bit worth actually reading.

- **a mask on the function itself** fails loudly. new build changes the code,
  the mask stops matching, you get `NotFound` or `Ambiguous`. good.
- **following a call** can fail quietly. if a new build adds a call earlier in
  the function, "the second call" is now some other perfectly real function,
  and you get its address with no error at all.
- **a fixed `Offset`** fails quietly the same way if the layout shifts.

so for those last two: check every build you list in `versions`, and ideally
write a second recipe that reaches the same thing a different way, so you can
compare them.

## builds you haven't checked

`versions` is the range of builds you've actually verified. `version()` gives
you the running `(major, build)`, and
`recipe.versions.applicability(major, build, 516)` tells you which case you're
in:

- `Some(Verified)`: you checked this build. use the result.
- `Some(ForwardCandidate)`: newer than anything you checked. the pattern might
  still match, but one unique match doesn't prove the answer is right.
- `None`: older than your range, or a different major version. skip it.

for the middle case, the `validation` module has cheap sanity checks: is the
address in a writable section, does any other code refer to it, does this
function really touch that field.

## scanning a file instead of a live process

`Module::from_parts` builds a module out of bytes you hand it:

```rust
use byond_scan::{Module, Signature, SignatureTreatment};

// `mov eax, [0x42B2EC]`, with the first byte sitting at address 0x500000
let bytes: &'static [u8] = &[0x90, 0xA1, 0xEC, 0xB2, 0x42, 0x00, 0x90];
let module = Module::from_parts(0, 0x500000, bytes);

let signature = Signature::new(SignatureTreatment::OffsetByInt(1), "A1 ?? ?? ?? ?? 90");
assert_eq!(signature.find(&module, "some_global"), Ok(0x42B2EC));
```

`from_parts_with_ranges` also takes the executable and writable ranges (the
`validation` checks need those), and `with_exports` attaches an export table so
`Anchor::Export` works. without one, a module built from bytes has no exports at
all. parsing the PE or ELF file to get them is on you. that's on purpose, so a
file parser never ends up linked into your plugin.

to check whether one mask is unique in a file:

```text
cargo run --example scan_file -- byondcore.dll "55 8B EC E8 ?? ?? ?? ?? 5D C3"
```

## a note on addresses

a live module gives you real runtime addresses on both platforms, so just use
them. `module.base()` is only for turning a number you pinned by hand (an
offset from the start of the module) into an address.

the bytes a live module scans are a copy, made the first time `Module::current()`
finds BYOND. the sections BYOND writes to are zeros in it. so `module.range()`
is for matching code, not for reading what a global holds right now. read the
address the scanner gave you for that.

## minimum Rust version

whatever `rust-version` in `Cargo.toml` says. CI builds on exactly that, so it
only goes up on purpose.

## license

[MPL-2.0](LICENSE.md)
