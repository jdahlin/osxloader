AC_PREREQ(2.59)

AC_INIT(osxloader, 0.1.0)
AC_CONFIG_SRCDIR(loader.c)
AC_CONFIG_AUX_DIR(config)

AM_INIT_AUTOMAKE(1.9)

AM_CONFIG_HEADER(config/config.h)

AM_MAINTAINER_MODE

AC_PROG_CC
AC_ISC_POSIX
AC_HEADER_STDC

dnl dl
AC_SEARCH_LIBS([dlopen], [dl], [], [AC_MSG_ERROR([*** dl library not found])])
AC_CHECK_HEADERS([dlfcn.h], [], [AC_MSG_ERROR([*** dl headers not found])])

dnl Capabilities
AC_SEARCH_LIBS([cap_init], [cap], [], [AC_MSG_ERROR([*** POSIX caps libraries not found])])
AC_CHECK_HEADERS([sys/capability.h], [], [AC_MSG_ERROR([*** POSIX caps headers not found])])

AC_CONFIG_FILES([
Makefile
])

AC_OUTPUT
