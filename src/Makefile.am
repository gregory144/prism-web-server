SUBDIRS = backends util huffman hpack http2 .

bin_PROGRAMS = conduit
conduit_SOURCES = backend.c tls.c server.c main.c
conduit_LDADD   = util/libhttp2_util.la huffman/libhpack_huffman.la hpack/libhpack.la http2/libhttp2.la

