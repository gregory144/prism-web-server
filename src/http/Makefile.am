SUBDIRS = h2 .

lib_LTLIBRARIES = libhttp.la
libhttp_la_CFLAGS = -I$(UTIL_DIR) -I$(top_srcdir) -I$(top_srcdir)/src
libhttp_la_SOURCES = request.c response.c http.c
libhttp_la_LIBADD = $(top_srcdir)/src/hpack/libhpack.la h2/libhttp2.la

TESTS = check_request
check_PROGRAMS = check_request

check_request_SOURCES = check_request.c
check_request_CFLAGS = @CHECK_CFLAGS@ -I$(UTIL_DIR) -I$(top_srcdir) -I$(top_srcdir)/src
check_request_LDADD = @CHECK_LIBS@ $(top_srcdir)/src/hpack/libhpack.la $(top_srcdir)/huffman/libhpack_huffman.la $(UTIL_DIR)/libhttp2_util.la
