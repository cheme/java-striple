java-striple
============

[striple](https://github.com/cheme/web3) support for jvm.

Build
-----

Use maven to build and test.

Status
------

WIP

This is a relatively straight forward port of the [rust](https://github.com/cheme/rust-striple) implementation which should be more documented.

 rust        | java 
 ------------------------
StripleIf    | Striple
Striple      | StripleImpl
StripleRef   | StripleImpl
...

For the time being documentation is very sparse, please refer to rust implementation.

Missing from rust impl :
- Loadable key kind from env_var
- Ripemd160/ED25519 owned scheme
- Storage attached file support (and general striple attached file support)

Overview
--------

* minimal dependency (bouncy castle), and simple design and api.

