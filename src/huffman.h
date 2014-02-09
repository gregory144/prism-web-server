/**
 *
 * Implements Huffman encoding/decoding for HPACK. See
 *
 * http://tools.ietf.org/html/draft-ietf-httpbis-header-compression-05
 */

#include <stdbool.h>

#ifndef HUFFMAN_H
#define HUFFMAN_H 

typedef struct huffman_entry_t {
  int index;
  int value;
  int left;
  int right;
} huffman_entry_t;

int get_bit(char* buffer, size_t i);

char* huffman_decode(char* buf, size_t len);

char* huffman_encode(char* buf, size_t len);

#endif
