# GTIRB Stack Stamp

This repository holds example implementations of binary
transformations implemented over top of
[GTIRB](https://github.com/grammatech/gtirb).  See the accompanying
[GTIRB
Tutorial](https://grammatech.github.io/gtirb/md_stack-stamp.html) for
more information.

Specifically, this example repository implements a transform to apply
'stack stamping' protections to a binary.

![stack-stamp signature graphic.](.stack-stamp.svg)

## Abstract

Stack stamping is a technique to help mitigate
<abbr title="Return Oriented Programming">ROP</abbr> style attacks.
This is done by 'stamping' the return address on the stack, thus
encrypting it.  Before it is popped off the stack and used, it is
decrypted by 'un-stamping' it.  This can be an efficient protection,
as no registers are needed, and while flags are affected, they are
only affected at function entry/exits where they do not need to be
preserved.  By encoding and decoding this return address, an attacker
has a more difficult task, since the replacement data would need to be
properly encoded, such that when it is un-stamped, it results in the
desired address.

## Building

This repository contains three implementations of stack-stamping in three
different languages:

1. [Python](#python)
2. [C++](#c)
3. [Common Lisp](#common-lisp)

### Python

The Python transform requires some dependencies to be installed:

```sh
pip3 install gtirb-capstone gtirb-functions capstone keystone-engine
```

To starting using it, run:

```sh
python3 setup.py develop
```

To invoke the command line utility thus generated:

```sh
python3 -m gtirb_stack_stamp
```

### C++

This transform depends on the following libraries:

* [Boost](https://www.boost.org/) (version 1.67 or later)
* [GTIRB](https://github.com/grammatech/gtirb)
* [Capstone](https://github.com/aquynh/capstone)
* [Keystone](https://github.com/keystone-engine/keystone)

Ensure they are installed before compiling the C++ version of the transform.
Building from source also depends on [CMake](https://cmake.org) being installed.

#### Options

We add the filling CMake options during building:

* `GTIRB_STACK_STAMP_ENABLE_TESTS`: Set to `OFF` to disable the downloading of
  Google Test and the building of the test executable. `ON` by default.
* `GTIRB_STACK_STAMP_BUILD_SHARED_LIBS`: Set to `OFF` to build static libraries
  instead of dybnamic ones. `ON` by default.

#### On Linux

```sh
cmake -Bbuild ./
cd build
make
```

The generated command-line utility will then be available in `build/bin`.

#### On Windows

Currently, [some](https://github.com/keystone-engine/keystone/issues/471)
[issues](https://github.com/keystone-engine/keystone/issues/472) are preventing
Keystone from being built on Windows, so the C++ version of gtirb-stack-stamp is
buildable on Linux only for the time being.

#### Tests

Our CMake automatically downloads a local copy of [Google Test](https://github.com/google/googletest)
and produces a test executable. To run it:

```sh
build/bin/test-gtirb-stack-stamp
```

You will need [gtirb-pprinter](https://github.com/grammatech/gtirb-pprinter)
and [ddisasm](https://github.com/grammatech/ddisasm) on your PATH.

### Common Lisp

The Common Lisp transform requires the following external libraries:
- [Capstone](https://github.com/aquynh/capstone)
- [Keystone](https://github.com/keystone-engine/keystone)

and the following common lisp packages
([gtirb](https://github.com/grammatech/gtirb),
 [gtirb-functions](https://github.com/grammatech/gtirb-functions),
 [gtirb-capstone](https://github.com/grammatech/gtirb-capstone))
which may be installed via QuickLisp:

1. Clone this repository into your `~/quicklisp/local-projects` directory
    ```sh
    git clone https://github.com/grammatech/gtirb-stack-stamp
    ```

2. Load `gtirb-stack-stamp` and all dependencies.
    ```lisp
    (ql:quickload :gtirb-stack-stamp)
    ```

To run the transform at the REPL:
```lisp
(write-gtirb (stack-stamp (drop-cfi (read-gtirb "in.gtirb"))) "out.gtirb")
```

To build the command line executable:
```sh
sbcl --eval '(ql:quickload :gtirb-stack-stamp)' \
     --eval '(asdf:make :gtirb-stack-stamp :type :program :monolithic t)'
```

To invoke the command line utility thus generated:
```sh
./stack-stamp --help
```

## Copyright and Acknowledgments

Copyright (C) 2020 GrammaTech, Inc.

This code is licensed under the MIT license. See the LICENSE file in
the project root for license terms.

This project is sponsored by the Office of Naval Research, One Liberty
Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
N68335-17-C-0700.  The content of the information does not necessarily
reflect the position or policy of the Government and no official
endorsement should be inferred.
