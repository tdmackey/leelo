//! Verify the same arithmetic and interpolation source files used by the crate.
#![allow(dead_code)]
#[path = "../crates/leelo-sss/src/gf256.rs"]
mod gf256;
#[path = "../crates/leelo-sss/src/interpolation.rs"]
mod interpolation;

fn main() {}
