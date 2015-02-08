dnl Process this file with autoconf to produce a configure script

AC_INIT(ams-whitelisting-tools,0~20150204,sam@samhobbs.co.uk)

dnl Place to store some helper files, keep the root dir cleaner
AC_CONFIG_AUX_DIR(config)

dnl Source directory
AC_CONFIG_SRCDIR(src/main.cpp)


AM_INIT_AUTOMAKE

dnl Check for c++ compiler
AC_PROG_CXX

dnl Check for sqlite3 library
AC_CHECK_LIB([sqlite3], [sqlite3_exec], [], [
        echo "The sqlite3 library is required for this program"
        exit -1])

dnl Check for boost library
AC_CHECK_LIB([boost_regex], [main], [], [
        echo "The boost regex library is required for this program"
        exit -1])

AC_LANG_PUSH([C++])
AC_CHECK_HEADERS([boost/regex.hpp], [],
    [AC_MSG_ERROR(You need the Boost libraries.)])
AC_LANG_POP([C++])

dnl Check for and enable c++0x compiler flag support using macro in m4 directory
dnl http://stackoverflow.com/questions/11909347/autotools-check-for-c11
AX_CXX_COMPILE_STDCXX_11

dnl List makefiles that the configure script should generate on the user's machine
dnl  for every Makefile.am we create, automake generates Makefile.in
dnl  The configure script will turn these into Makefiles
AC_OUTPUT(Makefile src/Makefile)
