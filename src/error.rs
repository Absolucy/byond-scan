// SPDX-License-Identifier: MPL-2.0
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Error {
	#[error("BYOND module base address unresolved")]
	ModuleNotFound,
	#[error("export not found: {0}")]
	ExportNotFound(&'static str),
	#[error("no match for: {0}")]
	NotFound(&'static str),
	/// more than one match, and we don't guess which one you meant.
	#[error("multiple matches for: {0}")]
	Ambiguous(&'static str),
	#[error("extraction ran out of instructions for: {0}")]
	DecodeExhausted(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;
