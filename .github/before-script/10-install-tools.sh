#!/bin/bash -efux

SCRIPT_DIR=$(dirname "${BASH_SOURCE[0]}")

source "${SCRIPT_DIR}/../config.sh"

# Download cpanm and make it executable as a standalone script
curl -L https://cpanmin.us -o cpanm
chmod 0755 cpanm

sudo ./cpanm --notest Test2::V0 > build.log 2>&1 \
    || (cat build.log && exit 1)

if [ "${APT_INSTALL-}" ]; then
    sudo apt-get install -y $APT_INSTALL
fi
