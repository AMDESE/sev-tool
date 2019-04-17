###############################################################################
# Copyright 2018 Advanced Micro Devices, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
###############################################################################

#!/bin/bash
# Script to build AMD SEV Tool

# Set to 1 to enable debugging or pass -d or --debug.
if [ "$(echo $1 | grep -E '^\-{0,2}d(ebug)?$')" != "" ]
then
    DEBUGGING=1
else
    DEBUGGING=0
fi

# If dependancies are needed
NEED_DEPS=0
INSTALLER=""
SSL_DEV=""

if [ ${DEBUGGING} -eq 1 ]
then
  debug()
  {
    echo -n "[ DEBUG ] LINE "
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
debug $LINENO ":" "OLD_DIR => " ${OLD_DIR}

OS_RELEASE=$(cat /etc/os-release)
debug $LINENO ":" "OS_RELEASE => " ${OS_RELEASE}

# Regular Expression to read /etc/os-release for major distributions.
ID_RE='ID\(\_LIKE\)\?\=\"\?[[:alpha:]]\+\([[:space:]][[:alpha:]]\*\)\?\"\?'

debug $LINENO ":" "ID_RE => " ${ID_RE}

# Read /etc/os-release to find the distribution base.
DIST_BASE=$(cat /etc/os-release | grep "${ID_RE}")

debug $LINENO ":" "DIST_BASE =>" ${DIST_BASE}
if [ "$(echo ${DIST_BASE} | grep 'suse')" != "" ] ||
   [ "$(echo ${DIST_BASE} | grep 'sles')" != "" ]
then
    # Cover all SLE and openSUSE distributions.
    debug $LINENO ":" "Distribution recognized as SUSE based"

    INSTALLER="zypper"
    SSL_DEV="libopenssl-devel"
    GCC_CPP="gcc-c++"
elif [ "$(echo ${DIST_BASE} | grep 'debian')" != "" ] ||
     [ "$(echo ${DIST_BASE} | grep 'ubuntu')" != "" ]
then
    # Cover all Debian and Ubuntu based distributions.
    debug $LINENO ":" "Distribution recognized as Debian or Ubuntu based"

    INSTALLER="apt-get"
    SSL_DEV="libssl-dev"
    GCC_CPP="g++"
elif [ "$(echo ${DIST_BASE} | grep 'fedora')" != "" ] ||
     [ "$(echo ${DIST_BASE} | grep 'rhel')" != "" ]
then
    # Cover all Redhat based distributions.
    debug $LINENO ":" "Distribution recognized as Fedora or Rhel based"

    INSTALLER="yum"
    SSL_DEV="openssl-devel"
    GCC_CPP="gcc-c++"
else
    debug $LINENO ":" "Regular expression could not match: \n" "${OS_RELEASE}"
    echo "Distribution not recognized. Please manually install "\
         "libelf libraries, make, zip, gcc, g++, git, wget, and libssl-dev." >&2
    exit 1
fi

debug $LINENO ":" "Checking for dependencies..."

# Check for all required dependancies
if [ "${INSTALLER}" = "zypper" ] || [ "${INSTALLER}" = "yum" ]
then
    if [ "$(rpm -q 'git' 2>&1 | grep 'not installed')" != "" ]        ||
       [ "$(rpm -q 'make' 2>&1 | grep 'not installed')" != "" ]       ||
       [ "$(rpm -q 'gcc' 2>&1 | grep 'not installed')" != "" ]        ||
       [ "$(rpm -q 'zip' 2>&1 | grep 'not installed')" != "" ]        ||
       [ "$(rpm -q 'wget' 2>&1 | grep 'not installed')" != "" ]       ||
       [ "$(rpm -q ${SSL_DEV} 2>&1 | grep 'not installed')" != "" ]   ||
       [ "$(rpm -q ${GCC_CPP} 2>&1 | grep 'not installed')" != "" ]
    then
        debug $LINENO ":" "A dependency is missing, setting flag!"
        NEED_DEPS=1
    fi
elif [ "${INSTALLER}" = "apt-get" ]
then
    if [ "$(dpkg -l 'git' 2>&1 | grep 'no packages')" != "" ]        ||
       [ "$(dpkg -l 'make' 2>&1 | grep 'no packages')" != "" ]       ||
       [ "$(dpkg -l 'gcc' 2>&1 | grep 'no packages')" != "" ]        ||
       [ "$(dpkg -l 'zip' 2>&1 | grep 'no packages')" != "" ]        ||
       [ "$(dpkg -l 'wget' 2>&1 | grep 'no packages')" != "" ]       ||
       [ "$(dpkg -l ${SSL_DEV} 2>&1 | grep 'no packages')" != "" ]   ||
       [ "$(dpkg -l ${GCC_CPP} 2>&1 | grep 'no packages')" != "" ]
    then
        debug $LINENO ":" "A dependency is missing, setting flag!"
        NEED_DEPS=1
    fi
fi

# Install dependencies if they are needed.
if [ ${NEED_DEPS} -eq 1 ]
then
    debug $LINENO ":" "A dependency is missing, installing now."
    debug $LINENO ":" "Running Command: \"sudo ${INSTALLER} install -y git make gcc "\
          "zip ${SSL_DEV} ${GCC_CPP}\""
    sudo ${INSTALLER} install -y git make gcc zip wget libssl-dev ${SSL_DEV} ${GCC_CPP}
fi

# Rebuild SEV Tool binary
cd src/
make clean
make -j64
cd ../

# Return to original directory
cd ${OLD_DIR}
