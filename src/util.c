#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include "util.h"

inline bool get_bit(char* buffer, size_t total_bit_index) {
  char* at_byte = buffer + (total_bit_index / 8);
  size_t bit_index = total_bit_index % 8;

  int b = *at_byte;
  int shifted = b >> (7 - bit_index);
  int res = shifted & 1;
  return res;
}

inline uint8_t get_bits8(char* buf, size_t offset, size_t num_bytes, uint8_t mask) {
  char* curr = buf + offset;
  uint8_t val = 0;
  for (; curr < buf + offset + num_bytes; curr++) {
    val = (val << 8) | *curr;
  }
  return val & mask;
}

inline uint16_t get_bits16(char* buf, size_t offset, size_t num_bytes, uint16_t mask) {
  char* curr = buf + offset;
  uint16_t val = 0;
  for (; curr < buf + offset + num_bytes; curr++) {
    val = (val << 8) | *curr;
  }
  return val & mask;
}

inline uint32_t get_bits32(char* buf, size_t offset, size_t num_bytes, uint32_t mask) {
  char* curr = buf + offset;
  uint32_t val = 0;
  for (; curr < buf + offset + num_bytes; curr++) {
    val = (val << 8) | *curr;
  }
  return val & mask;
}

