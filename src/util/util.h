
#ifndef HTTP_UTIL_H
#define HTTP_UTIL_H

#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <time.h>

#define UNUSED(expr) do { (void)(expr); } while (0)

/**
 * Copies a string to a new memory location
 * and terminates the string after len bytes
 */
#define COPY_STRING(dest, src, len) \
    dest = malloc(sizeof(char) * (len + 1)); \
    memcpy(dest, src, len); \
    dest[len] = '\0'

/**
 * If the given value is false, return false
 */
#define ASSERT_OR_RETURN_FALSE(value) \
  if (!value) { \
    return false; \
  }

/**
 * If the given value is false, return the value
 */
#define ASSERT_OR_RETURN_NULL(value) \
  if (!value) { \
    return NULL; \
  }

typedef struct {
  char * value;
  size_t length;
} string_and_length_t;

size_t roundup_to_power_of_2(size_t value);

bool get_bit(const uint8_t * const buffer, const size_t total_bit_index);

uint8_t get_bits8(const uint8_t * const buf, const uint8_t mask);

uint16_t get_bits16(const uint8_t * const buf, const uint16_t mask);

uint32_t get_bits32(const uint8_t * const buf, const uint32_t mask);

#define RFC1123_TIME_LEN 29

/*@null@*/ char * current_date_rfc1123(char * date_buf, size_t buf_len);

/*@null@*/ char * date_rfc1123(char * date_buf, size_t buf_len, time_t t);

#define TIME_WITH_MS_LEN 29

/*@null@*/ char * current_time_with_nanoseconds(char * date_buf, size_t buf_len);

#endif
