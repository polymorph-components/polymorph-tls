//! The `polymorph:tls` component crate. All content targets WASI; on other
//! targets this crate is empty (the cdylib exists only as a wasm
//! component).

#[cfg(all(target_family = "wasm", target_os = "wasi"))]
mod component;
#[cfg(all(target_family = "wasm", target_os = "wasi"))]
mod pump;

#[cfg(all(target_family = "wasm", target_os = "wasi"))]
pub(crate) use component::*;
