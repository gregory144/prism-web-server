lib_LTLIBRARIES = libhttp2.la
libhttp2_la_SOURCES = hash_table.c request.c response.c http.c
libhttp2_la_LIBADD = ../hpack/libhpack.la

TESTS = check_request check_hash_table
check_PROGRAMS = check_request check_hash_table

check_request_SOURCES = check_request.c
check_request_CFLAGS = @CHECK_CFLAGS@
check_request_LDADD = @CHECK_LIBS@

check_hash_table_SOURCES = check_hash_table.c
check_hash_table_CFLAGS = @CHECK_CFLAGS@
check_hash_table_LDADD = @CHECK_LIBS@
