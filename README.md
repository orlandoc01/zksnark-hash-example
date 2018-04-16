# zkSNARK Hash Circuit
## Table of Contents

- [Introduction](#introduction)
- [Build Guide](#build-guide)
  - [External Dependencies](#external-dependencies)
- [Directory Structure](#directory-structure)
- [Compilation](#compilation)


## Introduction

This application setups a simple zk-SNARK circuit that evaluates the following program:

```
sha256(password || salt) == hash
```

The program is constructed using `gadgetlib1` from `libsnark` to generate the proper R1CS constraints for the SHA256 hashing function. The application then uses this constraint system to run a simple zkSNARK according to the Groth16 protocol. The protocol is comprised of a setup phase, proving phase, and verification phase. The setup constructs the public keypair that the prover and verifier use. The prover provides their password, salt, and the resulting hash (along with the proving key) to construct a succinct proof. Any verifier is then able to verify this proof using the verification key and the hash. If the proof check passes, then the verifier knows that the proof creator knows the preimage of the hash without learning the content of the preimage.


## Build Guide

This repository has the following dependencies, which come from `libsnark`:

- C++ build environment
- CMake build infrastructure
- GMP for certain bit-integer arithmetic
- Fetched and compiled via Git submodules:
    - [libff](https://github.com/scipr-lab/libff) for finite fields and elliptic curves
    - [libfqfft](https://github.com/scipr-lab/libfqfft) for fast polynomial evaluation and interpolation in various finite domains
    - [Google Test](https://github.com/google/googletest) (GTest) for unit tests
    - [ate-pairing](https://github.com/herumi/ate-pairing) for the BN128 elliptic curve
    - [xbyak](https://github.com/herumi/xbyak) just-in-time assembler, for the BN128 elliptic curve

### External Dependencies

* On Ubuntu 16.04 LTS:

        $ sudo apt-get install build-essential cmake git libgmp3-dev libprocps4-dev python-markdown libboost-all-dev libssl-dev

* On Ubuntu 14.04 LTS:

        $ sudo apt-get install build-essential cmake git libgmp3-dev libprocps3-dev python-markdown libboost-all-dev libssl-dev

* On Fedora 21 through 23:

        $ sudo yum install gcc-c++ cmake make git gmp-devel python2-markdown

* On Fedora 20:

        $ sudo yum install gcc-c++ cmake make git gmp-devel python-markdown   

* On MacOS:

        $ brew install pkg-config openssl git
        
      
	*Note*: You will also need to add the following environment flags to ensure the C++ compiler can include the proper headers
	
```
export CPPFLAGS=-I/usr/local/opt/openssl/include
export LDFLAGS=-L/usr/local/opt/openssl/lib
export PKG_CONFIG_PATH=/usr/local/opt/openssl/lib/pkgconfig
```
     

## Directory Structure

* [__src__](src): C++ source code
* [__depends__](depends): dependency libraries

*Note*: An `.lvimrc` and `.ycm_extra_conf.py` is included for configuring a vim environment with the `YouCompleteMe` and `Ale` plugins


## Compilation

To compile this application, start by recursively fetching the dependencies.
```
git submodule update --init --recursive
```

Note, the submodules only need to be fetched once.

Next, initialize the `build` directory.
```
mkdir build && cd build && cmake ..
```

Lastly, compile the library.
```
make
```

To run the application, use the following command from the `build` directory:
```
./src/main
```

