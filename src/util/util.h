
#ifndef HTTP_UTIL_H
#define HTTP_UTIL_H

#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>

#define LOG_LEVEL_WARN true

#if defined LOG_LEVEL_FATAL

#define LOG_FATAL true
#define LOG_ERROR false
#define LOG_WARN false
#define LOG_INFO false
#define LOG_DEBUG false
#define LOG_TRACE false

#elif defined LOG_LEVEL_ERROR

#define LOG_FATAL true
#define LOG_ERROR true
#define LOG_WARN false
#define LOG_INFO false
#define LOG_DEBUG false
#define LOG_TRACE false

#elif defined LOG_LEVEL_WARN

#define LOG_FATAL true
#define LOG_ERROR true
#define LOG_WARN true
#define LOG_INFO false
#define LOG_DEBUG false
#define LOG_TRACE false

#elif defined LOG_LEVEL_INFO

#define LOG_FATAL true
#define LOG_ERROR true
#define LOG_WARN true
#define LOG_INFO true
#define LOG_DEBUG false
#define LOG_TRACE false

#elif defined LOG_LEVEL_DEBUG

#define LOG_FATAL true
#define LOG_ERROR true
#define LOG_WARN true
#define LOG_INFO true
#define LOG_DEBUG true
#define LOG_TRACE false

#elif defined LOG_LEVEL_TRACE

#define LOG_FATAL true
#define LOG_ERROR true
#define LOG_WARN true
#define LOG_INFO true
#define LOG_DEBUG true
#define LOG_TRACE true

#endif


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

uint8_t get_bits8(const uint8_t * const buf, const size_t offset, const uint8_t mask);

uint16_t get_bits16(const uint8_t * const buf, const size_t offset, const uint16_t mask);

uint32_t get_bits32(const uint8_t * const buf, const size_t offset, const uint32_t mask);

/*@null@*/ char * date_rfc1123();

void log_fatal(char * format, ...);

void log_error(char * format, ...);

void log_warning(char * format, ...);

void log_info(char * format, ...);

void log_debug(char * format, ...);

void log_trace(char * format, ...);

#endif
