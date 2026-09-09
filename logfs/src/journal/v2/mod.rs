//! Legacy v2 decoding and compatibility names.
//!
//! New journals are v3. These re-exports preserve the original API names.
pub(crate) use super::data;
pub use super::v3::{Journal2, Superblock, read, write};

mod codec;
pub(crate) mod index;
pub(super) use codec::*;
