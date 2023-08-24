#!/bin/bash

set -euxo pipefail

export RUSTFLAGS=-Dwarnings

(cd examples; cargo build --bins)

(cd ppproto; cargo build --no-default-features)
(cd ppproto; cargo build --no-default-features --features log)

# embedded
(cd ppproto; cargo build --target thumbv7em-none-eabi --no-default-features)
(cd ppproto; cargo build --target thumbv7em-none-eabi --no-default-features --features log)
(cd ppproto; cargo build --target thumbv7em-none-eabi --no-default-features --features defmt,smoltcp/defmt)
