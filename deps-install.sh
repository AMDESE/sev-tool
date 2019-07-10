#!/bin/bash
# Script to build AMD SEV Tool

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
    echo "$@"
  }
else
  debug()
  {
    echo -n ""
  }
fi

OS_RELEASE=$(cat /etc/os-release)
debug $LINENO ":" "OS_RELEASE => " ${OS_RELEASE}

# Regular Expression to read /etc/os-release for major distributions.
ID_RE='ID\(\_LIKE\)\?\=\"\?[[:alpha:]]\+\([[:space:]][[:alpha:]]\*\)\?\"\?'

debug $LINENO ":" "ID_RE => ${ID_RE}"

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
         "libelf libraries, make, zip, gcc, g++, git, wget, autoconf, and libssl-dev." >&2
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
       [ "$(rpm -q 'autoconf' 2>&1 | grep 'not installed')" != "" ]   ||
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
       [ "$(dpkg -l 'autoreconf' 2>&1 | grep 'no packages')" != "" ] ||
       [ "$(dpkg -l ${SSL_DEV} 2>&1 | grep 'no packages')" != "" ]   ||
       [ "$(dpkg -l ${GCC_CPP} 2>&1 | grep 'no packages')" != "" ]
    then
        debug $LINENO ":" "A dependency is missing, setting flag!"
        NEED_DEPS=1
    fi
fi

fcomp()
{
	debug $LINENO ":" "Attempting to determine which version number is greater."
	RETVAL=0

	if [ -n "${1}" ] && [ -n "${2}" ]
	then
		debug $LINENO ":" "Both arguments are non-zero values."
		debug $LINENO ":" "\${1} (SYSTEM_SSL_VERSION)  => ${1}"
		debug $LINENO ":" "\${2} (ACCEPTED_SSL_VERSIN) => ${2}"

		if [ "${1%.*}" \> "${2%.*}" ] && [ "${1#*.}" \> "${2#*.}" ] || [ "${1%.*}" \> "${2%.*}" ]
		then
			debug $LINENO ":" "The system SSL version is new enough to use."
			debug $LINENO ":" "\${1} (SYSTEM_SSL_VERSION)  => ${1}"
			debug $LINENO ":" "\${2} (ACCEPTED_SSL_VERSIN) => ${2}"
			RETVAL=1
		fi
	else
		debug $LINENO ":" "An error occured while attempting to parse the SSL version number."
		debug $LINENO ":" "\${1} (SYSTEM_SSL_VERSION)  => ${1}"
		debug $LINENO ":" "\${2} (ACCEPTED_SSL_VERSIN) => ${2}"
	fi

	return ${RETVAL}
}

check_ssl()
{
	SSL_VERSION="1.1.0j"
	ACCEPTED_SSL_VERSION="1.1.0"
	ACCEPTED_SSL_VER_TRUNK=$(echo "${ACCEPTED_SSL_VERSION}" | sed 's/.\{2\}$//')
	SYSTEM_SSL_VERSION=$(openssl version | awk '{print $2}' | sed "s/[a-zA-Z-]//g")
	SYSTEM_SSL_VER_TRUNK=$(echo "${SYSTEM_SSL_VERSION}" | sed 's/.\{2\}$//')

	CURRENT_DIR=$(pwd)

	if [ "$(fcomp ${SYSTEM_SSL_VER_TRUNK} ${ACCEPTED_SSL_VER_TRUNK})" = "0" ] &&
	   [ ! -d ./openssl/ ]
	then
		debug $LINENO ":" "Local directory of openssl not detected..."
		echo "Your version of openssl is not new enough!"
		echo "Would you like to build a self-contained instance of the required openssl version"
		printf "(internet connection required)? [y/N] "
		read -r ssl_response

		case ${ssl_response} in
			[yY]*)
				debug $LINENO ":" "User responded with YES."

				echo "Downloading, compiling, and building against openssl version ${SSL_VERSION}"

				# Download an acceptable version of openssl
				wget https://www.openssl.org/source/openssl-${SSL_VERSION}.tar.gz

				# create openssl directory
				mkdir -p openssl

				# Extract the tarball.
				tar -xf openssl-${SSL_VERSION}.tar.gz -C openssl --strip-components 1

				# Removing the tarball.
				rm -f openssl-${SSL_VERSION}.tar.gz

				# Enter the openssl directory, and build the library.
				cd openssl/ || exit
				./config
				make -j64

				cd "${CURRENT_DIR}" || exit

				# Remove system ssl libraries from src Makefile.am
				sed -i 's/^\# linked.*$//g' src/Makefile.am
				sed -i 's/^sevtool_LDADD.*$//g' src/Makefile.am

				# Add local ssl libraries to the src Makefile.am
				echo "SSL_DIR=../openssl" >> src/Makefile.am
				echo "sevtool_LDADD = \$(SSL_DIR)/libcrypto.a -ldl" >> src/Makefile.am
				echo "sevtool_CXXFLAGS += -isystem \$(SSL_DIR)/include -isystem \$(SSL_DIR)" >> src/Makefile.am
				;;
			*)
				debug $LINENO ":" "User responded with no."
				echo "You will need to make sure you manually install all required dependencies."
				;;
		esac
	elif [ "$(fcomp ${SYSTEM_SSL_VERSION} ${ACCEPTED_SSL_VERSION})" = "0" ] &&
		 [ -d ./openssl/ ]
	then
		debug $LINENO ":" "Local directory of openssl detected..."
		echo "Your version of openssl is not new enough!"
		printf "Would you like to locally compile and build against the appropriate version? [y/N] "
		read -r ssl_response

		case ${ssl_response} in
			[yY]*)
				# Enter the openssl directory, and rebuild the library.
				cd openssl/ || exit
				./config
				make -j64

				# No adjustments to the automake file should be necessary as they were already done once.

				cd "${CURRENT_DIR}" || exit
				;;
			*)
				debug $LINENO ":" "User responded with no."
				echo "You will need to make sure you manually install all required dependencies."
				;;
		esac
	else
		debug $LINENO ":" "Proper version of openssl detected as system install."
	fi
}

# Install dependencies if they are needed.
if [ ${NEED_DEPS} -eq 1 ]
then
	echo   "One or more required software dependencies are missing on your system."
	printf "Would you like to have them automatically installed? [y/N] "
	read -r response

	case ${response} in
		[yY]*)
			debug $LINENO ":" "User responded with YES."
			debug $LINENO ":" "Running Command: \"sudo ${INSTALLER} install -y git make gcc "\
				  "zip wget autoconf ${SSL_DEV} ${GCC_CPP}\""
			sudo ${INSTALLER} install -y git make gcc zip wget autoconf ${SSL_DEV} ${GCC_CPP}
			;;
		*)
			debug $LINENO ":" "User responded with no."
			echo "You will need to make sure you manually install all required dependencies."
			;;
	esac
fi

check_ssl

echo "With all dependencies met, you should be able to run \"autoreconf -if && ./configure && make\" to compile the sevtool."
