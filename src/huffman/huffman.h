/**
 *
 * Implements Huffman encoding/decoding for HPACK. See
 *
 * http://tools.ietf.org/html/draft-ietf-httpbis-header-compression-07#section-4.1.2
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
typedef struct {
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
typedef struct {
  uint16_t index;
  // the binary data used to represent the ASCII code
  uint32_t value;
  // the length in bits of the huffman code for this value
  uint8_t length;
} huffman_encoder_entry_t;

/**
 * A string + length pair
 */
typedef struct huffman_result_t {
  uint8_t* value;
  // length in octets
  size_t length;
} huffman_result_t;

/**
 * Decodes a HTTP2 huffman code into an ASCII string.
 *
 * See http://tools.ietf.org/html/draft-ietf-httpbis-header-compression-07
 */
bool huffman_decode(const uint8_t * const buf, const size_t len, huffman_result_t * const result);

/**
 * Encodes an ASCII string into HTTP2 huffman code.
 *
 * See http://tools.ietf.org/html/draft-ietf-httpbis-header-compression-07
 */
bool huffman_encode(const char * const buf, const size_t len, huffman_result_t * const result);

#endif
