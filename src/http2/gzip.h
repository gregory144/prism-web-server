#ifndef HTTP_GZIP_H
#define HTTP_GZIP_H

#include <stdint.h>
#include <stdbool.h>

#include <zlib.h>

#define GZIP_CHUNK 16384
#define GZIP_WINDOW_BITS (MAX_WBITS + 16)
#define GZIP_MEM_LEVEL 8
#define GZIP_MIN_SIZE 0x400

typedef struct {

  uint8_t * in;
  size_t in_length;

  uint8_t * out;
  size_t out_length;

  bool initialized;
  bool need_to_reset;

  z_stream stream;

} gzip_context_t;

gzip_context_t * gzip_compress_init(gzip_context_t * const context);

bool gzip_compress(gzip_context_t * const context);

void gzip_compress_free(gzip_context_t * const context);

uint8_t * gzip_decompress(uint8_t * const in, size_t in_length, size_t * out_length);

#endif
