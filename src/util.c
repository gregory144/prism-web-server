#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>

#include "util.h"

inline string_and_length_t* string_and_length(char* string, size_t length) {
  string_and_length_t* sl = malloc(sizeof(string_and_length_t));
  sl->value = string;
  sl->length = length;
  return sl;
}

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

static const char *DAY_NAMES[] =
  { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
static const char *MONTH_NAMES[] =
  { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

char* date_rfc1123() {
    const int RFC1123_TIME_LEN = 29;
    time_t t;
    struct tm* tm;
    char * buf = malloc(RFC1123_TIME_LEN+1);

    time(&t);
    tm = gmtime(&t);

    strftime(buf, RFC1123_TIME_LEN+1, "---, %d --- %Y %H:%M:%S GMT", tm);
    memcpy(buf, DAY_NAMES[tm->tm_wday], 3);
    memcpy(buf+8, MONTH_NAMES[tm->tm_mon], 3);

    return buf;
}
