SUBDIRS = backends util huffman hpack http .

bin_PROGRAMS = conduit
conduit_CFLAGS = -I$(UTIL_DIR)
conduit_SOURCES = backend.c tls.c server.c main.c
conduit_LDADD   = util/libhttp_util.la huffman/libhpack_huffman.la hpack/libhpack.la http/libhttp.la

