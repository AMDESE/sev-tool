#!/bin/bash
# Script to build AMD SEV Tool

# Set to 1 to enable debugging
DEBUGGING=0

if [ $DEBUGGING -eq 1 ]
then
  debug()
  {
    echo ""
    echo $@
  }
else
  debug()
  {
    echo -n ""
  }
fi

# save the current directory to we can go back to it at the end
OLD_DIR=$(pwd)
debug "OLD_DIR => " ${OLD_DIR}

OS_RELEASE=$(cat /etc/os-release)
debug "OS_RELEASE => " ${OS_RELEASE}

# Regular Expression to read /etc/os-release for major distributions.
ID_RE='ID\(\_LIKE\)\?\=\"\?[[:alpha:]]\+\([[:space:]][[:alpha:]]\*\)\?\"\?'

debug "ID_RE" ${ID_RE}

# Read /etc/os-release to find the distribution base.
DIST_BASE=$(cat /etc/os-release | grep "${ID_RE}")

debug "DIST_BASE =>" ${DIST_BASE}

# install libelf to be able to correctly build kernel modules/`uname,
# but only if it isn't already installed.
if [[ $DIST_BASE =~ 'suse' ]]
then
    # Cover all SLE and openSUSE distributions.

    debug "Distribution recognized as SUSE based"
    if [[ $(rpm -q libelf-devel 2>&1) =~ "not installed" ]]
    then
        echo "Missing libelf library dependency. Installing now..."
        sudo zypper in --non-interactive libelf-devel
    else
        echo "libelf libraries already installed, skipping installation."
    fi
elif [[ $DIST_BASE =~ 'debian' ]] || [[ $DIST_BASE =~ 'ubuntu' ]]
then
    # Cover all Debian and Ubuntu based distributions.
    debug "Distribution recognized as Debian or Ubuntu based"
    if [[ $(dpkg -l libelf-dev 2>&1) =~ "no packages found" ]]
    then
        echo "Missing libelf library dependency. Installing now..."
        sudo apt-get -y install libelf-dev
    else
        echo "libelf libraries already installed, skipping installation."
    fi
elif [[ $DIST_BASE =~ 'fedora' ]] || [[ $DIST_BASE =~ 'rhel' ]]
then
    # Cover all Redhat based distributions.
    debug "Distribution recognized as Fedora or Rhel based"
    if [[ $(rpm -q elfutils-libelf-devel 2>&1) =~ "not installed" ]]
    then
        # Using yum as this will be used for CentOS.
        echo "Missing libelf library dependency. Installing now..."
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

# Rebuild SEV Tool binary
cd src/
make clean
make -j64
cd ../

cd $old_dir
