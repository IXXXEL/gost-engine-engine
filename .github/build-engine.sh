#!/bin/bash -efux

source $(dirname "${BASH_SOURCE[0]}")/config.sh

PATH=$OPENSSL_INSTALL_PREFIX/bin:$PATH

mkdir -p build
cd build
cmake -DTLS13_PATCHED_OPENSSL=$PATCH_OPENSSL -DOPENSSL_ROOT_DIR=$OPENSSL_INSTALL_PREFIX \
    -DOPENSSL_ENGINES_DIR=$OPENSSL_INSTALL_PREFIX/engines ${ASAN-} ..
make
make test CTEST_OUTPUT_ON_FAILURE=1
if [ -z "${ASAN-}" ]; then
    make tcl_tests_engine
    make tcl_tests_provider
fi
