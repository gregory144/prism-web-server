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

typedef struct huffman_result_t {
  uint8_t* value;
  size_t length;
} huffman_result_t;

huffman_result_t* huffman_decode(uint8_t* buf, size_t len);

huffman_result_t* huffman_encode(uint8_t* buf, size_t len);

#endif
