SUBDIRS = util huffman hpack http2 .

bin_PROGRAMS = weta
weta_SOURCES = multimap.c server.c main.c
weta_LDADD   = ../lib/libuv.a util/libhttp2_util.la huffman/libhpack_huffman.la hpack/libhpack.la http2/libhttp2.la

TESTS = check_priority_queue
check_PROGRAMS = check_priority_queue

check_priority_queue_SOURCES = check_priority_queue.c
check_priority_queue_CFLAGS = @CHECK_CFLAGS@
check_priority_queue_LDADD = @CHECK_LIBS@
