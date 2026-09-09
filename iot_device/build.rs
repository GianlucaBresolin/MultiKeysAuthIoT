use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    fs::copy("link.ld", out_dir.join("link.ld"))
        .expect("Impossibile copiare link.ld in OUT_DIR");

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rerun-if-changed=link.ld");

    cc::Build::new()
        .file("src/boot.S")
        .compiler("aarch64-linux-gnu-gcc")
        .flag("-mcpu=generic")
        .flag("-nostdlib")
        .compile("boot");
    println!("cargo:rerun-if-changed=src/boot.S");
}