#!/bin/sh
# Script to build AMD SEV Tool

# save the current directory to we can go back to it at the end
old_dir=$(pwd)
echo $old_dir

# install libelf to be able to correctly build kernel modules/`uname
sudo apt --assume-yes install libelf-dev

# Fetch openssl submodule
git submodule init
git submodule update

# Config and make openssl
cd openssl/
./config
make -j64
cd ../

# Rename SEV Tool binary
cd src/
make clean
make -j64
cd ../

cd $old_dir
