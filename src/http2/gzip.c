#include <stdlib.h>
#include <string.h>

#include "gzip.h"

#include "../util/util.h"

#define GZIP_CHUNK 16384
#define GZIP_WINDOW_BITS (MAX_WBITS + 16)
#define GZIP_MEM_LEVEL 8
#define GZIP_MIN_SIZE 0x400

gzip_context_t * gzip_compress_init(gzip_context_t * context)
{
  if (!context) {
    context = malloc(sizeof(gzip_context_t));
    if (!context) {
      log_error("Unable to allocate space for gzip context");
      return NULL;
    }

    context->initialized = false;
    context->need_to_reset = false;

    context->in = NULL;
    context->in_length = 0;
    context->out = NULL;
    context->out_length = 0;

    z_stream * stream = &context->stream;
    stream->next_in = NULL;
    stream->avail_in = 0;
    stream->next_out = NULL;
    stream->avail_out = 0;

    stream->zalloc = Z_NULL;
    stream->zfree = Z_NULL;
    stream->opaque = Z_NULL;
  }

  if (!context->initialized) {
    int ret = deflateInit2(&context->stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, GZIP_WINDOW_BITS, GZIP_MEM_LEVEL,
                       Z_DEFAULT_STRATEGY);

    if (ret != Z_OK) {
      log_error("Could not initialize deflate routine: %d", ret);
      return NULL;
    }

    context->initialized = true;
  }

  return context;
}

bool gzip_compress(gzip_context_t * const context)
{

  z_stream * stream = &context->stream;

  uint8_t * out = malloc(sizeof(uint8_t) * context->in_length);
  size_t out_index = 0;

  if (!out) {
    log_error("Could not allocate space for gzip'd data");
    return false;
  }

  int ret;
  uint8_t out_chunk[GZIP_CHUNK];
  size_t out_chunk_length;

  if (context->need_to_reset) {
    ret = deflateReset(stream);

    if (ret != Z_OK) {
      log_error("Could not initialize deflate routine: %d", ret);
      return false;
    }

    context->need_to_reset = false;
  }

  stream->next_in = context->in;
  stream->avail_in = context->in_length;

  /* run deflate() on input until output buffer not full, finish
     compression if all of source has been read in */
  do {

    stream->avail_out = GZIP_CHUNK;
    stream->next_out = out_chunk;
    ret = deflate(stream, Z_FINISH);

    if (ret != Z_OK && ret != Z_STREAM_END) {
      context->need_to_reset = true;
      log_error("Deflation failed: %d", ret);
      return false;
    }

    out_chunk_length = GZIP_CHUNK - stream->avail_out;

    if (out_index + out_chunk_length > context->in_length) {
      context->need_to_reset = true;
      log_trace("Deflation output would be larger than input");
      return false;
    }

    memcpy(out + out_index, out_chunk, out_chunk_length);
    out_index += out_chunk_length;

  } while (stream->avail_out == 0);

  if (stream->avail_in != 0) {
    context->need_to_reset = true;
    log_error("Data left over after deflation: %ld", stream->avail_in);
    return false;
  }

  context->out = out;
  context->out_length = out_index;

  /* clean up and return */
  context->need_to_reset = true;
  return true;

}

void gzip_compress_free(gzip_context_t * const context)
{
  if (context->initialized) {
    (void)deflateEnd(&context->stream);
  }
  free(context);
}

uint8_t * gzip_decompress(uint8_t * const in, size_t in_length, size_t * out_length)
{
  size_t out_space = GZIP_CHUNK;
  uint8_t * out = malloc(sizeof(uint8_t) * out_space);

  if (!out) {
    log_error("Could not allocate space for inflated data");
    return NULL;
  }

  int ret;
  uint8_t out_chunk[GZIP_CHUNK];
  size_t out_index = 0;

  /* allocate inflate state */
  z_stream stream;
  stream.zalloc = Z_NULL;
  stream.zfree = Z_NULL;
  stream.opaque = Z_NULL;
  stream.avail_in = in_length;
  stream.next_in = in;
  ret = inflateInit2(&stream, GZIP_WINDOW_BITS);

  if (ret != Z_OK) {
    log_error("Inflate initialization failed: %d", ret);
    free(out);
    return NULL;
  }

  /* run inflate() on input until output buffer not full */
  do {

    stream.avail_out = GZIP_CHUNK;
    stream.next_out = out_chunk;

    ret = inflate(&stream, Z_NO_FLUSH);

    if (ret != Z_OK && ret != Z_STREAM_END) {
      (void)inflateEnd(&stream);
      log_error("Inflate returned stream error: %d", ret);
      free(out);
      return NULL;
    }

    size_t chunk_length = GZIP_CHUNK - stream.avail_out;

    if (out_index + chunk_length > out_space) {
      do {
        out_space += GZIP_CHUNK;
      } while (out_index + chunk_length > out_space);

      uint8_t * new_out = realloc(out, out_space);

      if (!new_out) {
        log_error("Could not allocate space for inflated data");
        free(out);
        return NULL;
      }

      out = new_out;
    }

    memcpy(out + out_index, out_chunk, chunk_length);
    out_index += chunk_length;

  } while (stream.avail_out == 0 || ret != Z_STREAM_END);

  *out_length = out_index;

  /* clean up and return */
  (void)inflateEnd(&stream);

  if (ret == Z_STREAM_END) {
    return out;
  } else {
    log_error("Unable to inflate data, Not at stream end: %d", ret);
    free(out);
    return NULL;
  }
}

