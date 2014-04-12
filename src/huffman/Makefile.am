lib_LTLIBRARIES = libhpack_huffman.la
libhpack_huffman_la_SOURCES = huffman.c
libhpack_huffman_la_LIBADD = ../util/libhttp2_util.la

bin_PROGRAMS = huffman
huffman_SOURCES = main.c
huffman_LDADD   = libhpack_huffman.la

TESTS = check_huffman
check_PROGRAMS = check_huffman

check_huffman_SOURCES = check_huffman.c
check_huffman_CFLAGS = @CHECK_CFLAGS@
check_huffman_LDADD = @CHECK_LIBS@
