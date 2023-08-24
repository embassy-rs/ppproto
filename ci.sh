#!/bin/bash

set -euxo pipefail

export RUSTFLAGS=-Dwarnings

# std
cargo build --no-default-features
cargo build --no-default-features --features log

# embedded
cargo build --target thumbv7em-none-eabi --no-default-features
cargo build --target thumbv7em-none-eabi --no-default-features --features log
cargo build --target thumbv7em-none-eabi --no-default-features --features defmt

# examples
(cd examples; cargo build --bins)
