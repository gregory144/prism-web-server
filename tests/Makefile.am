TESTS = check_hpack check_huffman check_util
check_PROGRAMS = check_hpack check_huffman check_util

check_hpack_SOURCES = check_hpack.c $(top_builddir)/src/hpack.c $(top_builddir)/src/util.c $(top_builddir)/src/hash_table.c $(top_builddir)/src/huffman.c $(top_builddir)/src/circular_buffer.c
check_hpack_CFLAGS = @CHECK_CFLAGS@
check_hpack_LDADD = @CHECK_LIBS@

check_huffman_SOURCES = check_huffman.c $(top_builddir)/src/huffman.c $(top_builddir)/src/util.c
check_huffman_CFLAGS = @CHECK_CFLAGS@
check_huffman_LDADD = @CHECK_LIBS@

check_util_SOURCES = check_util.c $(top_builddir)/src/util.c
check_util_CFLAGS = @CHECK_CFLAGS@
check_util_LDADD = @CHECK_LIBS@
