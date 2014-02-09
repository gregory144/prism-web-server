TESTS = check_hpack check_huffman
check_PROGRAMS = check_hpack check_huffman

check_hpack_SOURCES = check_hpack.c $(top_builddir)/src/hpack.c
check_hpack_CFLAGS = @CHECK_CFLAGS@
check_hpack_LDADD = @CHECK_LIBS@

check_huffman_SOURCES = check_huffman.c $(top_builddir)/src/huffman.c
check_huffman_CFLAGS = @CHECK_CFLAGS@
check_huffman_LDADD = @CHECK_LIBS@
