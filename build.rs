// Build script.
//
// NOTE: do NOT emit `cargo:rustc-link-lib=libc` here. That flag makes the
// linker look for `liblibc.so`, which does not exist — the C library is
// `libc.so` (linked as `-lc`). The `libc` Rust crate is a pure bindings
// crate, and rustc already links the C standard library (`-lc`) for the
// linux-gnu target, so mlockall/setrlimit/madvise resolve without any
// explicit link flag.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
}
