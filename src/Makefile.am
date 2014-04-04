SUBDIRS = util huffman hpack http2 .

bin_PROGRAMS = weta
weta_SOURCES = multimap.c server.c main.c
weta_LDADD   = ../lib/libuv.a util/libhttp2_util.la huffman/libhpack_huffman.la hpack/libhpack.la http2/libhttp2.la

