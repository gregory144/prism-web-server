
#ifndef HTTP_UTIL_H
#define HTTP_UTIL_H

#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>

#define LOG_LEVEL_FATAL 1

#if defined LOG_LEVEL_FATAL

#define LOG_FATAL 1

#elif defined LOG_LEVEL_ERROR

#define LOG_FATAL 1
#define LOG_ERROR 1

#elif defined LOG_LEVEL_WARN

#define LOG_FATAL 1
#define LOG_ERROR 1
#define LOG_WARN 1

#elif defined LOG_LEVEL_INFO

#define LOG_FATAL 1
#define LOG_ERROR 1
#define LOG_WARN 1
#define LOG_INFO 1

#elif defined LOG_LEVEL_DEBUG

#define LOG_FATAL 1
#define LOG_ERROR 1
#define LOG_WARN 1
#define LOG_INFO 1
#define LOG_DEBUG 1

#endif


#define UNUSED(expr) do { (void)(expr); } while (0)

typedef struct {
  char* value;
  size_t length;
} string_and_length_t;

inline string_and_length_t* string_and_length(char* string, size_t length);

inline bool get_bit(uint8_t* buffer, size_t total_bit_index);

inline uint8_t get_bits8(uint8_t* buf, size_t offset, size_t num_bytes, uint8_t mask);

inline uint16_t get_bits16(uint8_t* buf, size_t offset, size_t num_bytes, uint16_t mask);

inline uint32_t get_bits32(uint8_t* buf, size_t offset, size_t num_bytes, uint32_t mask);

char* date_rfc1123();

void log_warning(char* format, ...);

void log_debug(char* format, ...);

void log_info(char* format, ...);

void log_error(char* format, ...);

void log_fatal(char* format, ...);

#endif
