#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "util.h"

bool get_bit(const uint8_t * buffer, size_t total_bit_index) {
  const uint8_t* at_byte = buffer + (total_bit_index / 8);
  size_t bit_index = total_bit_index % 8;

  uint8_t b = *at_byte;
  uint8_t shifted = b >> (7 - bit_index);
  bool res = (bool)(shifted & 1);
  return res;
}

uint8_t get_bits8(uint8_t* buf, size_t offset, size_t num_bytes, uint8_t mask) {
  uint8_t* curr = buf + offset;
  uint8_t val = 0;
  for (; curr < buf + offset + num_bytes; curr++) {
    val = (val << 8) | *curr;
  }
  return val & mask;
}

uint16_t get_bits16(uint8_t* buf, size_t offset, size_t num_bytes, uint16_t mask) {
  uint8_t* curr = buf + offset;
  uint16_t val = 0;
  for (; curr < buf + offset + num_bytes; curr++) {
    val = (val << 8) | *curr;
  }
  return val & mask;
}

uint32_t get_bits32(uint8_t* buf, size_t offset, size_t num_bytes, uint32_t mask) {
  uint8_t* curr = buf + offset;
  uint32_t val = 0;
  for (; curr < buf + offset + num_bytes; curr++) {
    val = (val << 8) | *curr;
  }
  return val & mask;
}

static const char *DAY_NAMES[] =
  { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
static const char *MONTH_NAMES[] =
  { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
static const size_t RFC1123_TIME_LEN = 29;

/**
 * Returns the current date + time as a string as specified
 * by RFC1123
 *
 * Returns NULL if malloc or strftime fail.
 */
/*@null@*/ char* date_rfc1123() {
    time_t t;
    struct tm* tm;
    size_t buf_len = RFC1123_TIME_LEN + 1;
    char* date_buf = malloc(sizeof(char) * buf_len);
    ASSERT_OR_RETURN_NULL(date_buf);

    t = time(NULL);
    tm = gmtime(&t);

    if (strftime(date_buf, buf_len, "---, %d --- %Y %H:%M:%S GMT", tm) < 1) {
      log_fatal("Unable to get date as string\n");
      free(date_buf);
      return NULL;
    }
    memcpy(date_buf, DAY_NAMES[tm->tm_wday], 3);
    memcpy(date_buf+8, MONTH_NAMES[tm->tm_mon], 3);

    return date_buf;
}

#define LOG_WITH_LEVEL(level) \
  va_list ap; \
  fprintf(stdout, "%s\t", level); \
  va_start(ap, format); \
  if (vfprintf(stdout, format, ap) < 0) { \
    abort(); \
  } \
  va_end(ap);

void log_fatal(char* format, ...) {
  if (LOG_FATAL) {
    LOG_WITH_LEVEL("FATAL")
  }
}

void log_warning(char* format, ...) {
  if (LOG_WARN) {
    LOG_WITH_LEVEL("WARN")
  }
}

void log_error(char* format, ...) {
  if (LOG_ERROR) {
    LOG_WITH_LEVEL("ERROR")
  }
}

void log_info(char* format, ...) {
  if (LOG_INFO) {
    LOG_WITH_LEVEL("INFO")
  }
}

void log_debug(char* format, ...) {
  if (LOG_DEBUG) {
    LOG_WITH_LEVEL("DEBUG")
  }
}

void log_trace(char* format, ...) {
  if (LOG_TRACE) {
    LOG_WITH_LEVEL("TRACE")
  }
}
