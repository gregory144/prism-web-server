SUBDIRS = backends util huffman hpack http2 .

bin_PROGRAMS = conduit
conduit_SOURCES = backend.c blocking_queue.c tls.c server.c main.c
conduit_LDADD   = util/libhttp2_util.la huffman/libhpack_huffman.la hpack/libhpack.la http2/libhttp2.la

TESTS = check_priority_queue check_blocking_queue
check_PROGRAMS = check_priority_queue check_blocking_queue

check_priority_queue_SOURCES = check_priority_queue.c
check_priority_queue_CFLAGS = @CHECK_CFLAGS@
check_priority_queue_LDADD = @CHECK_LIBS@

check_blocking_queue_SOURCES = check_blocking_queue.c
check_blocking_queue_CFLAGS = @CHECK_CFLAGS@
check_blocking_queue_LDADD = @CHECK_LIBS@
