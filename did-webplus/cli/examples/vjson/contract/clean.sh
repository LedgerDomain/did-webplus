#!/bin/bash -x
set -eo pipefail
IFS=$'\n\t'
# See http://redsymbol.net/articles/unofficial-bash-strict-mode/

# This cleans all the generated artifacts from run.sh (see .gitignore)

rm -f \
    Alice.* \
    AliceSignature.* \
    Bob.* \
    BobSignature.* \
    CompletedContract.schema.json \
    CompletedContract.schema.url \
    CompletedRadDeal.* \
    Contract.schema.json \
    Contract.schema.url \
    RadDeal.* \
    SignatureOnContract.schema.json \
    SignatureOnContract.schema.url
