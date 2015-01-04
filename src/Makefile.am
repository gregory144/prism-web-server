SUBDIRS = plugins util huffman hpack http .

bin_PROGRAMS = prism
prism_CFLAGS = -I$(UTIL_DIR)
prism_SOURCES = server_config.c plugin.c tls.c worker.c client.c server.c main.c
prism_LDADD   = util/libhttp_util.la huffman/libhpack_huffman.la hpack/libhpack.la http/libhttp.la

