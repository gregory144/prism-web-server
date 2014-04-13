#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "util.h"

string_and_length_t* string_and_length(const char* string, size_t length) {
  string_and_length_t* sl = malloc(sizeof(string_and_length_t));
  sl->value = string;
  sl->length = length;
  return sl;
}

bool get_bit(const uint8_t* buffer, size_t total_bit_index) {
  const uint8_t* at_byte = buffer + (total_bit_index / 8);
  size_t bit_index = total_bit_index % 8;

  int b = *at_byte;
  int shifted = b >> (7 - bit_index);
  int res = shifted & 1;
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

char* date_rfc1123() {
    const int RFC1123_TIME_LEN = 29;
    time_t t;
    struct tm* tm;
    char* buf = malloc(RFC1123_TIME_LEN+1);

    time(&t);
    tm = gmtime(&t);

    strftime(buf, RFC1123_TIME_LEN+1, "---, %d --- %Y %H:%M:%S GMT", tm);
    memcpy(buf, DAY_NAMES[tm->tm_wday], 3);
    memcpy(buf+8, MONTH_NAMES[tm->tm_mon], 3);

    return buf;
}

#define LOG_WITH_LEVEL(level) \
  va_list ap; \
  fprintf(stdout, "%s\t", level); \
  va_start(ap, format); \
  vfprintf(stdout, format, ap); \
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
