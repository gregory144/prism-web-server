/**
 *
 * Implements Huffman encoding/decoding for HPACK. See
 *
 * http://tools.ietf.org/html/draft-ietf-httpbis-header-compression-05
 */

#ifndef HUFFMAN_H
#define HUFFMAN_H 

#include <stdbool.h>

typedef struct huffman_decoder_entry_t {
  int index;
  int value;
  int left;
  int right;
} huffman_decoder_entry_t;

typedef struct huffman_encoder_entry_t {
  uint16_t index;
  // the binary data used to represent the ascii code
  uint32_t value;
  uint8_t length;
} huffman_encoder_entry_t;

char* huffman_decode(char* buf, size_t len);

char* huffman_encode(char* buf, size_t len);

#endif
