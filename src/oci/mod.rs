//! Reading, validating and lowering the OCI runtime configuration.
//!
//! Configuration handling here is a compiler, not an interpreter:
//!
//! ```text
//!   config.json  ->  Spec      borrowed from a memory mapping, no copies
//!                ->  validate  every rule checked once, in the driver
//!                ->  Plan      a flat arena of exactly what to do
//! ```
//!
//! The plan crosses into the container init process as bytes in a sealed
//! memory file. Because it is a single contiguous arena addressed by offsets
//! rather than pointers, it needs no serialisation format: the arena is the
//! wire format, and the executor that applies it cannot allocate, because
//! there is nothing reachable from it to allocate from.

#![deny(missing_docs)]

pub mod json;
pub mod lower;
pub mod parse;
mod parse_linux;
pub mod plan;
pub mod spec;

pub use spec::Spec;
