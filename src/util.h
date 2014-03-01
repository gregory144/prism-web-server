
#ifndef HTTP_UTIL_H
#define HTTP_UTIL_H

#include <stdint.h>
#include <stdbool.h>

#define UNUSED(expr) do { (void)(expr); } while (0)

typedef struct {
  char* value;
  size_t length;
} string_and_length_t;

inline string_and_length_t* string_and_length(char* string, size_t length);

inline bool get_bit(char* buffer, size_t total_bit_index);

inline uint8_t get_bits8(char* buf, size_t offset, size_t num_bytes, uint8_t mask);

inline uint16_t get_bits16(char* buf, size_t offset, size_t num_bytes, uint16_t mask);

inline uint32_t get_bits32(char* buf, size_t offset, size_t num_bytes, uint32_t mask);

char* date_rfc1123();

#endif
