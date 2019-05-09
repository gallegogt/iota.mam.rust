// iota-mam-sys/build.rs
use std::process::Command;

macro_rules! get(($name:expr) => (ok!(env::var($name))));
macro_rules! ok(($expression:expr) => ($expression.unwrap()));
macro_rules! log {
    ($fmt:expr) => (println!(concat!("iota-mam-sys/build.rs:{}: ", $fmt), line!()));
    ($fmt:expr, $($arg:tt)*) => (println!(concat!("iota-mam-sys/build.rs:{}: ", $fmt),
    line!(), $($arg)*));
}
macro_rules! log_var(($var:ident) => (log!(concat!(stringify!($var), " = {:?}"), $var)));


fn main() {
    build::main();
}

fn run<F>(name: &str, mut configure: F)
    where F: FnMut(&mut Command) -> &mut Command
{
    let mut command = Command::new(name);
    let configured = configure(&mut command);
    log!("Executing {:?}", configured);
    if !ok!(configured.status()).success() {
        panic!("failed to execute {:?}", configured);
    }
    log!("Command {:?} finished successfully", configured);
}


#[cfg(not(feature = "bundled"))]
mod build {
    pub fn main() {
        bindings::place_bindings(Vec::new())
    }
}

#[cfg(not(feature = "build_bindgen"))]
mod bindings {
    const IOTA_ENTANGLED_VERSION : &'static str = "develop";
    use std::{env, fs};
    use std::path::Path;

    pub fn place_bindings(_inc_dir: Vec<&str>) {
        let out_dir = env::var("OUT_DIR").unwrap();
        let out_path = Path::new(&out_dir).join("bindings.rs");

        let bindings = format!("bindings/bindings_iota_entangled_c_{}.rs", IOTA_ENTANGLED_VERSION);
        fs::copy(&bindings, out_path)
            .expect("Could not copy bindings to output directory")
    }
}

#[cfg(feature = "build_bindgen")]
mod bindings {
    extern crate bindgen;

    use std::env;
    use std::path::PathBuf;

    pub fn place_bindings(inc_dir: Vec<&str> ) {
        let cver = bindgen::clang_version();
        println!("debug:clang version: {}", cver.full);
        println!("debug:bindgen include path: {:?}", inc_dir);

        // The bindgen::Builder is the main entry point
        // to bindgen, and lets you build up options for
        // the resulting bindings.
        let bindings = bindgen::Builder::default()
            // Older clang versions (~v3.6) improperly mangle the functions.
            // We shouldn't require mangling for straight C library. I think.
            .trust_clang_mangling(false)
            // The input header we would like to generate
            // bindings for.
            .header("wrapper.h").clang_args(inc_dir)
            // Finish the builder and generate the bindings.
            .generate()
            // Unwrap the Result and panic on failure.
            .expect("Unable to generate bindings");

        // Write the bindings to the $OUT_DIR/bindings.rs file.
        let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
        bindings
            .write_to_file(out_path.join("bindings.rs"))
            .expect("Couldn't write bindings!");
    }
}


#[cfg(feature = "bundled")]
mod build {
    extern crate semver;
    extern crate glob;

    use crate::run;
    use crate::bindings;

    use std::error::Error;
    use std::path::{Path, PathBuf};
    use std::process;
    use std::{env, fs};
    use std::process::Command;
    use semver::Version;
    use glob::glob;

    const MIN_BAZEL: &'static str = "0.5.4";

    fn format_target<'a>() -> Vec<&'a str> {
        vec![
            "--",
            "common/errors",
            // "common/crypto/curl-p:all",
            "common/crypto/ftroika:all",
            "utils:memset_safe",
            // "common/crypto/iss:all",
            // "common/crypto/kerl:all",
            // "common/model:all",
            // "common/helpers:all",
            // "common/trinary:all",
            "mam/sponge:all",
            "mam/trits:all",
            "mam/prng:all",
            "mam/mam:all",
            "mam/api:all",
            // "mam/mss:all",
            // "mam/ntru:all",
            "mam/pb3:all",
            // "mam/psk:all",
            "mam/troika:all",
            // "mam/wots:all",

        ]
    }

    pub fn main () {
        // we rerun the build if the `build.rs` file is changed.
        println!("cargo:rerun-if-changed=build.rs");

        // Mske sure that the Git submodule is checked out
        if !Path::new("entangled/.git").exists() {
            let _ = Command::new("git")
                    .args(&["submodule", "update", "--init"])
                    .status();
        }
        build_from_src();
    }

    fn build_from_src() {

        let output = PathBuf::from(&get!("OUT_DIR"));
        log_var!(output);
        let source = PathBuf::from("entangled/");
        log_var!(source);

        let lib_dir = output; //.join(format!("lib-{}", LIB_OUTPUT));
        log_var!(lib_dir);

        if lib_dir.exists() {
            log!("Directory {:?} already exists", lib_dir);
        } else {
            log!("Creating directory {:?}", lib_dir);
            fs::create_dir(lib_dir.clone()).unwrap();
        }

        if let Err(e) = check_bazel() {
            println!("cargo:error=Bazel must be installed at version {} or greater. (Error: {})",
                    MIN_BAZEL,
                    e);
            process::exit(1);
        }

        // Allows us to pass in --incompatible_load_argument_is_label=false
        let bazel_args_string = if let Ok(args) = env::var("ENTANGLED_RUST_BAZEL_OPTS") {
            args
        } else {
            "".to_string()
        };

        run("bazel", |command| {
            command.current_dir(&source)
                .arg("build")
                .arg(format!("--jobs={}", get!("NUM_JOBS")))
                .arg("--compilation_mode=opt")
                .arg("--copt=-march=native")
                .args(bazel_args_string.split_whitespace())
                .args(format_target())
        });

        bindings::place_bindings(
            vec![
                "-I./entangled",
                "-I./entangled/bazel-bin",
                "-I./entangled/bazel-bin/external/com_github_uthash/_virtual_includes/uthash",
                "-I./entangled/bazel-bin/external/keccak/_virtual_includes/keccak",
                "-I./entangled/bazel-bin/external/keccak/_virtual_includes/keccak_sponge_1600",
                "-I./entangled/bazel-bin/external/keccak/_virtual_includes/keccak_sponge_common",
                "-I./entangled/bazel-bin/external/keccak/_virtual_includes/common",
                "-I./entangled/bazel-bin/external/keccak/_virtual_includes/snp_1600_reference",
            ]);

        println!("cargo:root={}", lib_dir.display());
        copy_libs_glob(
            vec![
                "entangled/bazel-bin/mam/**/*.a",
                "entangled/bazel-bin/common/crypto/ftroika/**/*.a",
                "entangled/bazel-bin/common/*.a",
                "entangled/bazel-bin/utils/*.a",
            ]
        , &lib_dir);

        println!("cargo:rustc-link-search=native={}", lib_dir.display());
    }
    ///
    /// glob_patterns:  Vector of String
    /// lib_dir: Path of the libs
    ///
    fn copy_libs_glob<'a>(glob_patterns: Vec<&'a str>, lib_dir: &PathBuf) {
        glob_patterns.iter().for_each(|glob_pattern| {
            for entry in glob(glob_pattern).expect("Failed to read glob pattern") {
                match entry {
                    Ok(ref path) => {
                        if let Some(file_name) = &path.file_name() {
                            println!("FILE NAME: {}", file_name.to_str().unwrap());
                            let libname = file_name.to_str().unwrap();
                            let library_path = lib_dir.join(&libname);
                            log!("Copying {:?} to {:?}", path, library_path);

                            match fs::copy(path, library_path) {
                                Ok(_) => {
                                    println!("File Copied");
                                }
                                Err(e) => {
                                    log!("{:?}", e);
                                }
                            }

                            println!("cargo:rustc-link-lib=static={}", &libname.replace("lib", "").replace(".a", ""));
                            println!("cargo:rustc-link-search=native={}", lib_dir.display());
                        }
                    },
                    Err(e) => println!("{:?}", e),
                }
            }
        })
    }

    ///
    /// Check bazel
    ///
    fn check_bazel() -> Result<(), Box<Error>> {
        let mut command = Command::new("bazel");
        command.arg("version");
        log!("Executing {:?}", command);
        let out = command.output()?;
        log!("Command {:?} finished successfully", command);
        let stdout = String::from_utf8(out.stdout)?;
        let mut found_version = false;
        for line in stdout.lines() {
            if line.starts_with("Build label:") {
                found_version = true;
                let mut version_str = line.split(":")
                    .nth(1)
                    .unwrap()
                    .split(" ")
                    .nth(1)
                    .unwrap()
                    .trim();
                if version_str.ends_with('-') {
                    // hyphen is 1 byte long, so it's safe
                    version_str = &version_str[..version_str.len() - 1];
                }
                let version = Version::parse(version_str)?;
                let want = Version::parse(MIN_BAZEL)?;
                if version < want {
                    return Err(format!("Installed version {} is less than required version {}",
                                    version_str,
                                    MIN_BAZEL)
                        .into());
                }
            }
        }
        if !found_version {
            return Err("Did not find version number in `bazel version` output.".into());
        }
        Ok(())
    }
}
