lib_LTLIBRARIES = libhttp2.la
libhttp2_la_SOURCES = gzip.c request.c response.c http.c
libhttp2_la_LIBADD = ../hpack/libhpack.la

TESTS = check_request
check_PROGRAMS = check_request

check_request_SOURCES = check_request.c
check_request_CFLAGS = @CHECK_CFLAGS@
check_request_LDADD = @CHECK_LIBS@
