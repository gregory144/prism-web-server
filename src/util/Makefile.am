lib_LTLIBRARIES = libhttp2_util.la
libhttp2_util_la_SOURCES = util.c multimap.c binary_buffer.c

TESTS = check_util check_multimap check_binary_buffer
check_PROGRAMS = check_util check_multimap check_binary_buffer

check_util_SOURCES = check_util.c
check_util_CFLAGS = @CHECK_CFLAGS@
check_util_LDADD = @CHECK_LIBS@

check_multimap_SOURCES = check_multimap.c
check_multimap_CFLAGS = @CHECK_CFLAGS@
check_multimap_LDADD = @CHECK_LIBS@

check_binary_buffer_SOURCES = check_binary_buffer.c
check_binary_buffer_CFLAGS = @CHECK_CFLAGS@
check_binary_buffer_LDADD = @CHECK_LIBS@
