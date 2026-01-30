#!/bin/bash -efux

SCRIPT_DIR=$(dirname "${BASH_SOURCE[0]}")

source "${SCRIPT_DIR}/../config.sh"

cd "${SCRIPT_DIR}/../../openssl"
git describe --always --long

mkdir -p ${OPENSSL_INSTALL_PREFIX}

${SETARCH-} ./config shared -d --prefix=$OPENSSL_INSTALL_PREFIX --libdir=lib --openssldir=$OPENSSL_INSTALL_PREFIX \
	${OPENSSL_USE_RPATH:+-Wl,-rpath=$OPENSSL_INSTALL_PREFIX/lib}
${SETARCH-} make -s -j$(nproc) build_libs
${SETARCH-} make -s -j$(nproc) build_programs
make -s install_sw
