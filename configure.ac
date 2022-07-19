dnl Init the autoconf process
dnl (Program Name and Version Number)
AC_INIT(sev-tool, 1.7)


dnl Safety checks in case user overwritten --srcdir
AC_CONFIG_SRCDIR(./src/sevapi.h)

dnl Store the auxiliary build tools (e.g., install-sh, config.sub, config.guess)
dnl in this dir (build-aux)
AC_CONFIG_AUX_DIR(build-aux)

dnl Check that OpenSSL is >= 1.1.0 by looking for version specific APIs
dnl OpenSSL 1.1.1.x uses EVP_PKEY_base_id
dnl OpenSSL 3.0.x renamed to EVP_PKEY_get_base_id
AC_SEARCH_LIBS(
	EVP_PKEY_base_id,
	crypto,
	[],
	[AC_SEARCH_LIBS(
		EVP_PKEY_get_base_id,
		crypto,
		[],
		[AC_MSG_ERROR(
			[Incompatible version of OpenSSL found]
		)]
	)]
)

dnl Commented out because we are currently using sev-tool/lib/psp-sev.h
dnl
dnl Ensure that the SEV header is present in glibc.
dnl AC_CHECK_HEADER(/usr/include/linux/psp-sev.h, [],
dnl                 [AC_MSG_ERROR([Necessary libraries are missing])])

dnl Init automake, and specify this program use relaxed structures.
dnl i.e. this program doesn't follow the gnu coding standards, and doesn't have
dnl ChangeLog, COPYING, AUTHORS, INSTALL, README etc. files.
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

AC_CANONICAL_HOST

build_linux=no
build_windows=no
build_mac=no

case "${host_os}" in
	linux*)
		build_linux=yes
		;;
	cygwin*|mingw*)
		build_windows=yes
		;;
	darwin*)
		build_mac=yes
		;;
	*)
		AC_MSG_ERROR(["OS $host_os is not supported"])
		;;
esac

AM_CONDITIONAL([LINUX], [test "$build_linux" = "yes"])
AM_CONDITIONAL([WINDOWS], [test "$build_windows" = "yes"])
AM_CONDITIONAL([OSX], [test "$build_mac" = "yes"])

dnl Check for C++ compiler
AC_PROG_CXX

dnl Tells automake to create a Makefile
dnl See https://www.gnu.org/software/automake/manual/html_node/Requirements.html
AC_CONFIG_FILES([Makefile src/Makefile])

dnl Generate the output
AC_OUTPUT
