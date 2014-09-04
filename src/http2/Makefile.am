lib_LTLIBRARIES = libhttp2.la
libhttp2_la_CFLAGS = -I$(UTIL_DIR) -I$(top_srcdir) -I$(top_srcdir)/src
libhttp2_la_SOURCES = gzip.c request.c response.c http.c
libhttp2_la_LIBADD = ../hpack/libhpack.la

TESTS = check_request
check_PROGRAMS = check_request

check_request_SOURCES = check_request.c
check_request_CFLAGS = @CHECK_CFLAGS@ -I$(UTIL_DIR) -I$(top_srcdir) -I$(top_srcdir)/src
check_request_LDADD = @CHECK_LIBS@ ../hpack/libhpack.la ../huffman/libhpack_huffman.la ../util/libhttp2_util.la
