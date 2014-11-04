lib_LTLIBRARIES = libhttp2.la
libhttp2_la_CFLAGS = -I$(UTIL_DIR) -I$(top_srcdir) -I$(top_srcdir)/src
libhttp2_la_SOURCES = h2_error.c h2_frame.c h2.c
libhttp2_la_LIBADD = $(top_srcdir)/src/hpack/libhpack.la

TESTS = check_h2_frame
check_PROGRAMS = check_h2_frame

check_h2_frame_SOURCES = check_h2_frame.c
check_h2_frame_CFLAGS = @CHECK_CFLAGS@ -I$(UTIL_DIR) -I$(top_srcdir) -I$(top_srcdir)/src
check_h2_frame_LDADD = @CHECK_LIBS@ $(top_srcdir)/src/util/libhttp_util.la
