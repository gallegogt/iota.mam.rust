# IOTA MAM Rust Client Library

This repository contains the source for [IOTA MAM](https://github.com/iotaledger/entangled/tree/develop/mam) Rust library


## Features

------

The initial version of the library is a wrapper for the MAM C library, and I will try to include all of the features available in the C library for the last version


## Building the Crate

------


The library is a standard Rust "crate" using the Cargo build tool. It uses the standard cargo commands for building:

```bash
$ cargo build
```

Builds the library, and also build the *-sys* subcrate and the bundled *Entangled MAM* C library

```bash
$ cargo build --examples
```

[Is no ready yet] Builds the library and samples applications in the examples directory.


```bash
$ cargo test
```

Builds and runs the unit tests

```bash
$ cargo doc
```

Generates reference documentation.


## The MAM C Library and iota-mam-sys

The IOTA MAM Rust crate is a wrapper around the *Entangled Mam C* Library. The project includes a Rust -sys crate, called iota-mam-sys, which provides unsafe bindings to the C library. The repository contains a Git submodule pointing to the specific version of the C library that the Rust crate requires, and by default, it will automatically build and link to that library, using pre-generated C bindings that are also included in the repo.

When building, the user has several options:

Build the bundled library using the pre-generated bindings (default).

Build the bundled library, but regenerate the bindings at build time.
<!-- Use an external library, with the location specified by environment variables, generating the bindings at build time. -->
Use the pre-installed library with the pre-generated bindings.

These are chosen with cargo features, explained below.

Currently the Rust library is only linking to the following libs:

  * libchannel.a
  * libendpoint.a
  * libmessage.a
  * libmam_channel_t_set.a
  * libmam_endpoint_t_set.a
  * libmam_pk_t_set.a
  * libapi.a
  * libtrit_t_to_mam_msg_read_context_t_map.a
  * libtrit_t_to_mam_msg_write_context_t_map.a


### Building the bundled *Entangled MAM C* library

This is the default:

```bash
$ cargo build
```

This will initialize and update th C library from C library sources from Git, then use the *bazel* build system to build the static version of the C libraries, and link it in.

When building the bundled libraries, the bindings can also be regenerated at build-time. This is especially useful when building on uncommon/untested platforms to ensure proper bindings for that system. This is done using the "buildtime_bindgen" feature:

```
$ cargo build --features "build_bindgen"
```

In this case it will generate bindings based on the header files in the bundled C repository,


### Bindgen linker issue

The crate can optionally use the Rust bindgen library to create the bindings to the *Entangled MAM* C library.

Bindgen requires a relatively recent version of the Clang library installed on the system - recommended v3.9 or 4.0. The bindgen dependencies seem, however, to seek out the oldest Clang version if multiple ones are installed on the system. On Ubuntu 14.04 or 16.04, the Clang v3.6 default might give some problems, although as the MAM builder is currently configured, it should work.

But the safest thing would be to set the LIBCLANG_PATH environment variable to point to a supported version, like:

````
export LIBCLANG_PATH=/usr/lib/llvm-3.9/lib
````

## Status of Development



## Example

