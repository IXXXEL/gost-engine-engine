#!/bin/bash -efux

SCRIPT_DIR=$(dirname "${BASH_SOURCE[0]}")

${SCRIPT_DIR}/before-script/10-install-tools.sh
${SCRIPT_DIR}/before-script/20-pull-openssl.sh
${SCRIPT_DIR}/before-script/30-build-openssl.sh
