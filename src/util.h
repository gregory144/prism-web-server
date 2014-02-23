
#ifndef HTTP_UTIL_H
#define HTTP_UTIL_H

#include <stdint.h>
#include <stdbool.h>

#define UNUSED(expr) do { (void)(expr); } while (0)

inline bool get_bit(char* buffer, size_t total_bit_index);

inline uint8_t get_bits8(char* buf, size_t offset, size_t num_bytes, uint8_t mask);

inline uint16_t get_bits16(char* buf, size_t offset, size_t num_bytes, uint16_t mask);

inline uint32_t get_bits32(char* buf, size_t offset, size_t num_bytes, uint32_t mask);

#endif
