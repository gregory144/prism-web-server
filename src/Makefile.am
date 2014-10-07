SUBDIRS = backends util huffman hpack http .

bin_PROGRAMS = synapse
synapse_CFLAGS = -I$(UTIL_DIR)
synapse_SOURCES = backend.c tls.c server.c main.c
synapse_LDADD   = util/libhttp_util.la huffman/libhpack_huffman.la hpack/libhpack.la http/libhttp.la

