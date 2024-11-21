#!/bin/bash -x
set -eo pipefail
IFS=$'\n\t'
# See http://redsymbol.net/articles/unofficial-bash-strict-mode/

# This script is used to generate the Default schema using the did-webplus CLI tool.
# The default schema is special because it's its own schema and requires special
# handling to generate the VJSON.

DID_WEBPLUS_BIN="$HOME/.cargo/bin/did-webplus"
if [ ! -f "$DID_WEBPLUS_BIN" ]; then
    echo "did-webplus not found at $DID_WEBPLUS_BIN.  Please install it by running 'cargo install --path did-webplus-cli' in the 'did-webplus' repository root dir."
    exit 1
fi

export RUST_BACKTRACE=1
export RUST_LOG=did-webplus=trace,vjson=trace,debug

# Special logic for the Default schema
$DID_WEBPLUS_BIN vjson default-schema --no-newline > src/schema/Default.schema.json
cat src/schema/Default.schema.json | jq -jr '.["$id"]' > src/schema/Default.schema.url
