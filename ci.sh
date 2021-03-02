#!/bin/bash

set -euxo pipefail

(cd examples; cargo build --bins)

(cd ppproto; cargo build --no-default-features)
(cd ppproto; cargo build --no-default-features --features logging-log)

# embedded
(cd ppproto; cargo build --target thumbv7em-none-eabi --no-default-features)
(cd ppproto; cargo build --target thumbv7em-none-eabi --no-default-features --features logging-log)
(cd ppproto; cargo build --target thumbv7em-none-eabi --no-default-features --features logging-defmt)
