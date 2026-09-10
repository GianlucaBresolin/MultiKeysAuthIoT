use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    fs::copy("link.ld", out_dir.join("link.ld"))
        .expect("Impossibile copiare link.ld in OUT_DIR");

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rerun-if-changed=link.ld");

    let mut build = cc::Build::new();
    build.file("src/boot.S");

    if cfg!(target_os = "macos") {
        build.compiler("clang");
        build.flag("--target=aarch64-none-elf");
    } else {
        build.compiler("aarch64-linux-gnu-gcc");
    }

    build.flag("-mcpu=generic");
    build.flag("-nostdlib");
    build.compile("boot");

    println!("cargo:rerun-if-changed=src/boot.S");
}