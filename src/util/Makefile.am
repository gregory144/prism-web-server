lib_LTLIBRARIES = libhttp_util.la
libhttp_util_la_SOURCES = util.c base64url.c multimap.c binary_buffer.c hash_table.c blocking_queue.c atomic_int.c

TESTS = check_util check_multimap check_binary_buffer check_hash_table check_priority_queue check_blocking_queue check_base64url
check_PROGRAMS = check_util check_multimap check_binary_buffer check_hash_table check_priority_queue check_blocking_queue check_base64url

check_util_SOURCES = check_util.c
check_util_CFLAGS = @CHECK_CFLAGS@
check_util_LDADD = @CHECK_LIBS@

check_multimap_SOURCES = check_multimap.c
check_multimap_CFLAGS = @CHECK_CFLAGS@
check_multimap_LDADD = @CHECK_LIBS@

check_binary_buffer_SOURCES = check_binary_buffer.c
check_binary_buffer_CFLAGS = @CHECK_CFLAGS@
check_binary_buffer_LDADD = @CHECK_LIBS@

check_hash_table_SOURCES = check_hash_table.c
check_hash_table_CFLAGS = @CHECK_CFLAGS@
check_hash_table_LDADD = @CHECK_LIBS@

check_priority_queue_SOURCES = check_priority_queue.c
check_priority_queue_CFLAGS = @CHECK_CFLAGS@
check_priority_queue_LDADD = @CHECK_LIBS@

check_blocking_queue_SOURCES = check_blocking_queue.c
check_blocking_queue_CFLAGS = @CHECK_CFLAGS@
check_blocking_queue_LDADD = @CHECK_LIBS@

check_base64url_SOURCES = check_base64url.c binary_buffer.c util.c
check_base64url_CFLAGS = @CHECK_CFLAGS@
check_base64url_LDADD = @CHECK_LIBS@
