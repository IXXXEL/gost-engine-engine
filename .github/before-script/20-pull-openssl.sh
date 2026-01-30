#!/bin/bash -efux

SCRIPT_DIR=$(dirname "${BASH_SOURCE[0]}")

source "${SCRIPT_DIR}/../config.sh"

cd "$SCRIPT_DIR/../../"

git clone --depth 1 -b $OPENSSL_BRANCH https://github.com/openssl/openssl.git
if [ "${PATCH_OPENSSL}" == "1" ]; then
    git apply patches/openssl-tls1.3.patch
fi