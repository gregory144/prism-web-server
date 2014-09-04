lib_LTLIBRARIES = libhpack.la
libhpack_la_CFLAGS = -I$(UTIL_DIR) -I$(top_srcdir) -I$(top_srcdir)/src
libhpack_la_SOURCES = header_list.c circular_buffer.c hpack.c
libhpack_la_LIBADD = ../huffman/libhpack_huffman.la

TESTS = check_hpack
check_PROGRAMS = check_hpack

check_hpack_SOURCES = check_hpack.c
check_hpack_CFLAGS = @CHECK_CFLAGS@ -I$(UTIL_DIR) -I$(top_srcdir) -I$(top_srcdir)/src
check_hpack_LDADD = @CHECK_LIBS@ ../huffman/libhpack_huffman.la ../util/libhttp2_util.la
