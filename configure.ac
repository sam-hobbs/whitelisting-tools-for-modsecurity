dnl Process this file with autoconf to produce a configure script
AC_INIT([ams-whitelisting-tools],[0~150222],[sam@samhobbs.co.uk])

dnl Require a recent version of autoconf
AC_PREREQ([2.59])

dnl Place to store some helper files, keep the root dir cleaner
AC_CONFIG_AUX_DIR(config)

AM_INIT_AUTOMAKE

dnl specify source directory
AC_CONFIG_SRCDIR(src/main.cpp)

dnl create a config.h file (Automake will add -DHAVE_CONFIG_H)
AC_CONFIG_HEADER([config.h])

dnl Check for c++ compiler
AC_LANG(C++)

dnl set c++ compiler
AC_PROG_CXX

dnl Check for sqlite3 library
AC_CHECK_LIB([sqlite3], [sqlite3_exec], [], [
        echo "The sqlite3 library is required for this program"
        exit -1])

dnl Check for boost library using the macros in the m4 directory
dnl Only tested with boost_regex version 1.55
AX_BOOST_BASE([1.55], [], [
	echo "The boost regex library is required for this program"
	exit -1])
	

dnl BOOST_FILESYSTEM requires AX_BOOST_SYSTEM
dnl These macros create flags for the linker, the src/Makefile.am must use them, e.g. "auditlog2db_LDADD = $(BOOST_REGEX_LIB) $(BOOST_FILESYSTEM_LIB) $(BOOST_SYSTEM_LIB)"
AX_BOOST_REGEX
AX_BOOST_FILESYSTEM
AX_BOOST_SYSTEM

dnl For boost m4 macro examples see:
dnl http://www.randspringer.de/boost/examples.html
dnl Requires some modifications to Makefile.am

dnl Check for and enable c++0x compiler flag support using macro in m4 directory
AX_CXX_COMPILE_STDCXX_11

dnl List makefiles that the configure script should generate on the user's machine
dnl  for every Makefile.am we create, automake generates Makefile.in
dnl  The configure script will turn these into Makefiles
AC_OUTPUT(Makefile src/Makefile doc/Makefile)
