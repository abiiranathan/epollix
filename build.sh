#!/bin/env bash
set -ex

WORKING_DIR=$(pwd)
TEMP="$WORKING_DIR/temp"
INSTALL_DEPENDENCIES="NO"

mkdir -p "$TEMP"
cd "$TEMP"

# Detect OS and install dependencies
# Detect OS and install dependencies
installDependencies() {
    OS=$(uname -s)

    if [[ "$OS" == "Linux" ]]; then
        if command -v apt-get &> /dev/null; then
            sudo apt-get update
            sudo apt-get install -y libssl-dev libsodium-dev zlib1g-dev pkg-config libcjson-dev build-essential ninja-build libblocksruntime-dev
        elif command -v pacman &> /dev/null; then
            sudo pacman -Syu --noconfirm openssl libsodium zlib pkg-config cjson make ninja libdispatch
        else
            echo "Unsupported Linux distribution"
            exit 1
        fi
    else
        echo "Unsupported operating system: $OS"
        exit 1
    fi
}

if [[ "$INSTALL_DEPENDENCIES" == "YES" ]]; then
installDependencies
fi

# Download solidc
rm -rf solidc
git clone --depth=1 -b main https://github.com/abiiranathan/solidc.git
cd solidc
mkdir -p build
make configure && make build
sudo make install

# navigate back to temp directory
cd "$TEMP"

# Download cipherkit
rm -rf cipherkit
git clone --depth=1 -b main https://github.com/abiiranathan/cipherkit.git
cd cipherkit
make
sudo make install

# Back to project root
cd $WORKING_DIR

# Now build epollix library in current directory
make
sudo make install

# Cleanup
rm -rf $TEMP
