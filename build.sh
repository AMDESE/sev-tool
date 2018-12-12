#!/bin/sh
# Script to build AMD SEV Tool

# save the current directory to we can go back to it at the end
old_dir=$(pwd)
echo $old_dir

# Regular Expression to read /etc/os-release for major distributions.
ID_RE='ID_\?(LIKE)\?\=\"\?[[:alnum:]]\+[[:space:]]\?[[:alnum:]]\+\?\"\?'

# Grab only the value in between ID_LIKE or ID.
REPLACE_RE='s/ID_\?\(LIKE\)\?=\"\(.*\)\"/\2/'

# Read /etc/os-release to find the distribution base.
DIST_BASE=$(cat /etc/os-release | grep "${ID_RE}" | sed "${REPLACE_RE}")

# install libelf to be able to correctly build kernel modules/`uname,
# but only if it isn't already installed.
if [[ $DIST_BASE =~ 'suse' ]]
then
    # Cover all SLE and openSUSE distributions.

    if [[ $(rpm -q libelf-devel 2>&1) =~ "not installed" ]]
    then
        sudo zypper in --non-interactive libelf-devel
    else
        echo "libelf libraries already installed, skipping installation."
    fi
elif [[ $DIST_BASE =~ 'debian' ]] || [[ $DIST_BASE =~ 'ubuntu' ]]
then
    # Cover all Debian and Ubuntu based distributions.

    if [[ $(dpkg -l libelf-dev 2>&1) =~ "no packages found" ]]
    then
        sudo apt-get -y install libelf-dev
    else
        echo "libelf libraries already installed, skipping installation."
    fi
elif [[ $DIST_BASE =~ 'fedora' ]] || [[ $DIST_BASE =~ 'rhel' ]]
then
    # Cover all Redhat based distributions.

    if [[ $(rpm -q elfutils-libelf-devel 2>&1) =~ "not installed" ]]
    then
        # Using yum as this will be used for CentOS.
        sudo yum install -y elfutils-libelf-devel
    else
        echo "libelf libraries already installed, skipping installation."
    fi
fi

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
