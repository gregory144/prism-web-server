
lib_LTLIBRARIES = libhttp2.la
libhttp2_la_CFLAGS = -I$(UTIL_DIR) -I$(top_srcdir) -I$(top_srcdir)/src
libhttp2_la_SOURCES = h2_error.c h2_frame.c h2.c
libhttp2_la_LIBADD = $(top_srcdir)/src/hpack/libhpack.la

TESTS = check_h2_frame check_h2
check_PROGRAMS = check_h2_frame check_h2

check_h2_frame_SOURCES = check_h2_frame.c
check_h2_frame_CFLAGS = @CHECK_CFLAGS@ -I$(UTIL_DIR) -I$(top_srcdir) -I$(top_srcdir)/src
check_h2_frame_LDADD = @CHECK_LIBS@ $(top_srcdir)/src/util/libhttp_util.la

check_h2_SOURCES = check_h2.c
check_h2_CFLAGS = @CHECK_CFLAGS@ -I$(UTIL_DIR) -I$(top_srcdir) -I$(top_srcdir)/src
check_h2_LDADD = @CHECK_LIBS@ libtestcmd.a $(top_srcdir)/src/util/libhttp_util.la $(top_srcdir)/src/hpack/libhpack.la

noinst_LIBRARIES = libtestcmd.a
libtestcmd_a_SOURCES = h2_test_cmd_parser.h h2_test_cmd_scanner.h h2_test_cmd_parser.y h2_test_cmd_scanner.l h2_test_cmd.c
libtestcmd_a_CFLAGS = -I$(UTIL_DIR) -I$(top_srcdir) -I$(top_srcdir)/src -Wno-error
libtestcmd_a_YFLAGS = --defines=h2_test_cmd_parser.h
libtestcmd_a_LFLAGS = --header-file=h2_test_cmd_scanner.h

h2_test_cmd_scanner.h: h2_test_cmd_scanner.c
	test -f $@ || rm -f h2_test_cmd_scanner.c
	test -f $@ || $(MAKE) $(AM_MAKEFLAGS) h2_test_cmd_scanner.c

h2_test_cmd_parser.h: h2_test_cmd_scanner.c
	test -f $@ || rm -f h2_test_cmd_scanner.c
	test -f $@ || $(MAKE) $(AM_MAKEFLAGS) h2_test_cmd_parser.c

BUILT_SOURCES = h2_test_cmd_parser.c h2_test_cmd_parser.h h2_test_cmd_scanner.c h2_test_cmd_scanner.h

