#!/bin/bash
# Script to build AMD SEV Tool

# Set to 1 to enable debugging
DEBUGGING=0

# If dependancies are needed
NEED_DEPS=0
INSTALLER=""
LIBELF_NAME=""
DEPENDENCIES=(git make gcc zip)

if [ ${DEBUGGING} -eq 1 ]
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

debug "ID_RE => " ${ID_RE}

# Read /etc/os-release to find the distribution base.
DIST_BASE=$(cat /etc/os-release | grep "${ID_RE}")

debug "DIST_BASE =>" ${DIST_BASE}

if [[ ${DIST_BASE} =~ 'suse' ]]
then
    # Cover all SLE and openSUSE distributions.
    debug "Distribution recognized as SUSE based"

    INSTALLER="zypper"
    LIBELF_NAME="libelf-devel"
    GCC_CPP="gcc-c++"
elif [[ ${DIST_BASE} =~ 'debian' ]] || [[ ${DIST_BASE} =~ 'ubuntu' ]]
then
    # Cover all Debian and Ubuntu based distributions.
    debug "Distribution recognized as Debian or Ubuntu based"

    INSTALLER="apt-get"
    LIBELF_NAME="libelf-dev"
    GCC_CPP="g++"
elif [[ ${DIST_BASE} =~ 'fedora' ]] || [[ ${DIST_BASE} =~ 'rhel' ]]
then
    # Cover all Redhat based distributions.
    debug "Distribution recognized as Fedora or Rhel based"

    INSTALLER="yum"
    LIBELF_NAME="elfutils-libelf-devel"
    GCC_CPP="gcc-c++"
else
    debug "Regular expression could not match: \n" "${OS_RELEASE}"
    echo "Distribution not recognized. Please manually install "\
         "libelf libraries, make, zip, gcc, g++, and git." >&2
    exit 1
fi

debug "Checking for dependencies..."

# Check for all required dependancies
if [[ ${INSTALLER} = "zypper" ]] || [[ ${INSTALLER} = "yum" ]]
then
    for package in ${DEPENDENCIES[@]}
    do
        if [[ $(rpm -q ${package} 2>&1) =~ "not installed" ]]
        then
            ${NEED_DEPS}=1
            break
        fi
    done
elif [[ ${INSTALLER} = "apt-get" ]]
then
    for package in ${DEPENDENCIES[@]}
    do
        if [[ $(dpkg -l ${package} 2>&1) =~ "no packages found" ]]
        then
            ${NEED_DEPS}=1
            break
        fi
    done
fi

# Install dependencies if they are needed.
if [[ ${NEED_DEPS} -eq 1 ]]
then
    debug "A dependency is missing, installing now."
    debug "Running Command: \"sudo ${INSTALLER} -y install "\
          "${LIBELF_NAME} ${DEPENDENCIES[@]} ${GCC_CPP}\""
    sudo ${INSTALLER} -y install ${LIBELF_NAME} ${DEPENDENCIES[@]} ${GCC_CPP}
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

# Return to original directory
cd ${OLD_DIR}
