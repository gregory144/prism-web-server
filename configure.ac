AC_INIT([prism],[0.0.1],[greg@gtgross.com])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])

AC_GNU_SOURCE

# archiver for libraries
AM_PROG_AR
AM_SILENT_RULES([yes])

AC_PROG_CC
AC_PROG_CC_C99
AC_PROG_CXX
AM_PROG_LIBTOOL
AC_PROG_RANLIB

AC_CHECK_PROGS([DOXYGEN], [doxygen])
if test -z "$DOXYGEN";
  then AC_MSG_WARN([Doxygen not found - continuing without Doxygen support])
fi

AC_CHECK_HEADERS([stdint.h])
AC_CHECK_HEADERS([stdlib.h])
AC_CHECK_HEADERS([string.h])
AC_CHECK_HEADERS([limits.h])
AC_CHECK_HEADERS([stddef.h])
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([memmove])
AC_CHECK_FUNCS([memset])
AC_CHECK_FUNCS([strchr])
AC_CHECK_FUNCS([strdup])
AC_CHECK_FUNCS([strpbrk])
AC_CHECK_FUNCS([strtoul])
AC_CHECK_FUNCS([getcwd])
AC_CHECK_FUNCS([realpath])
AC_CHECK_FUNCS([strncasecmp])
AC_CHECK_FUNCS([strrchr])
AC_CHECK_FUNCS([strtol])
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_UINT64_T
AC_FUNC_ERROR_AT_LINE

# libtool
LT_INIT

# suggested by libtoolize
AC_CONFIG_MACRO_DIR([m4])

# check for 'check' executable
PKG_CHECK_MODULES([CHECK], [check >= 0.9.4])

AC_CHECK_LIB(uv, uv_run)
# require pthread for libuv
AC_CHECK_LIB(pthread, pthread_create)
AC_CHECK_LIB(crypto, BIO_new, , [AC_MSG_ERROR(library crypto not found)])
AC_CHECK_LIB(ssl, SSL_CTX_new, , [AC_MSG_ERROR(library ssl not found)])
AC_CHECK_LIB(ssl, SSL_CTX_set_alpn_select_cb, [AC_DEFINE(HAVE_ALPN, [1], [Define if ALPN support exists])], [AC_MSG_WARN(ALPN support missing)])
AC_CHECK_LIB(z, zlibVersion)

# required for 'check'
AM_PROG_CC_C_O

AC_SUBST(UTIL_DIR, `pwd`/src/util)

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile
                 docs/Makefile
                 src/plugins/framer/Makefile
                 src/plugins/debug/Makefile
                 src/plugins/files/Makefile
                 src/plugins/Makefile
                 src/util/Makefile
                 src/huffman/Makefile
                 src/hpack/Makefile
                 src/http/h2/Makefile
                 src/http/h1_1/Makefile
                 src/http/Makefile
                 src/Makefile])


AM_CONDITIONAL([HAVE_DOXYGEN],
               [test -n "$DOXYGEN"])AM_COND_IF([HAVE_DOXYGEN], [AC_CONFIG_FILES([docs/Doxyfile])])

AC_OUTPUT

