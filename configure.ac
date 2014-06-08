AC_INIT([conduit],[0.0.1],[greg@gtgross.com])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])

AC_PROG_CC
AC_PROG_CC_C99

AC_CHECK_HEADERS([stdint.h])
AC_CHECK_HEADERS([stdlib.h])
AC_CHECK_HEADERS([string.h])
AC_CHECK_HEADERS([limits.h])
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([memmove memset strchr strdup strpbrk strtoul])
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# archiver for libraries
AM_PROG_AR

# libtool
LT_INIT

# suggested by libtoolize
AC_CONFIG_MACRO_DIR([m4])

AC_CHECK_LIB(uv, uv_run)
# require pthread for libuv
AC_CHECK_LIB(pthread, pthread_create)
AC_CHECK_LIB(z, zlibVersion)

# check for 'check' executable
PKG_CHECK_MODULES([CHECK], [check >= 0.9.4])

# required for 'check'
AM_PROG_CC_C_O

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile src/util/Makefile src/huffman/Makefile src/hpack/Makefile src/http2/Makefile src/Makefile])

AC_OUTPUT

