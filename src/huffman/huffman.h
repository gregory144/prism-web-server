/**
 *
 * Implements Huffman encoding/decoding for HPACK. See
 *
 * http://tools.ietf.org/html/draft-ietf-httpbis-header-compression-05
 */

#ifndef HUFFMAN_H
#define HUFFMAN_H

#include <stdbool.h>
#include <stdint.h>

/**
 * The generated file huffman_decoder_data.c creates an array of entries that form a tree
 * structure. The tree is navigated from the last entry until a value is found. When you see
 * a 0 in the huffman code, navigate left in the tree, otherwise, navigate right.
 */
typedef struct huffman_decoder_entry_t {
  uint16_t index;
  int16_t value; // can be -1
  int16_t left; // can be -1
  int16_t right; // can be -1
} huffman_decoder_entry_t;

/**
 * The generated file huffman_encoder_data.c creates an array of entries used to
 * lookup each ASCII value. The index corresponds to the ASCII code of the character
 * to encode.
 */
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

/**
 *
 */
huffman_result_t* huffman_decode(const uint8_t* buf, size_t len);

huffman_result_t* huffman_encode(const uint8_t* buf, size_t len);

#endif
