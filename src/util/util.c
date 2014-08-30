#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "util.h"

#define LOG_FILE stdout

/**
 *
 * Round this value to the next highest power of 2
 *
 * See http://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2
 *
 */
size_t roundup_to_power_of_2(size_t v)
{

  // TODO - does this work for values greater than 2^32?

  v--;
  v |= v >> 1;
  v |= v >> 2;
  v |= v >> 4;
  v |= v >> 8;
  v |= v >> 16;
  v++;

  return v;
}

bool get_bit(const uint8_t * const buffer, const size_t total_bit_index)
{
  const uint8_t * at_byte = buffer + (total_bit_index / 8);
  size_t bit_index = total_bit_index % 8;

  uint8_t b = *at_byte;
  uint8_t shifted = b >> (7 - bit_index);
  bool res = (bool)(shifted & 1);
  return res;
}

uint8_t get_bits8(const uint8_t * const buf, const uint8_t mask)
{
  const size_t num_bytes = 1;
  const uint8_t * curr = buf;
  uint8_t val = 0;

  for (; curr < buf + num_bytes; curr++) {
    val = (val << 8) | *curr;
  }

  return val & mask;
}

uint16_t get_bits16(const uint8_t * const buf, const uint16_t mask)
{
  const size_t num_bytes = 2;
  const uint8_t * curr = buf;
  uint16_t val = 0;

  for (; curr < buf + num_bytes; curr++) {
    val = (val << 8) | *curr;
  }

  return val & mask;
}

uint32_t get_bits32(const uint8_t * const buf, const uint32_t mask)
{
  const size_t num_bytes = 4;
  const uint8_t * curr = buf;
  uint32_t val = 0;

  for (; curr < buf + num_bytes; curr++) {
    val = (val << 8) | *curr;
  }

  return val & mask;
}

static const char * DAY_NAMES[] =
{ "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
static const char * MONTH_NAMES[] = {
  "Jan", "Feb", "Mar", "Apr", "May", "Jun",
  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

/**
 * Returns the current date + time as a string as specified
 * by RFC1123
 *
 * Returns NULL if malloc or strftime fail.
 */
/*@null@*/ char * current_date_rfc1123(char * date_buf, size_t buf_len)
{
  time_t t;
  t = time(&t);

  return date_rfc1123(date_buf, buf_len, t);
}

/**
 * Returns the given date + time as a string as specified
 * by RFC1123
 *
 * Returns NULL if malloc or strftime fail.
 */
/*@null@*/ char * date_rfc1123(char * date_buf, size_t buf_len, time_t t)
{
  struct tm * tm;

  if (date_buf == NULL) {
    date_buf = malloc(sizeof(char) * buf_len);
    buf_len = RFC1123_TIME_LEN + 1;
  }

  ASSERT_OR_RETURN_NULL(date_buf);

  tm = gmtime(&t);

  if (strftime(date_buf, buf_len, "---, %d --- %Y %H:%M:%S GMT", tm) < 1) {
    log_fatal("Unable to get date as string");
    free(date_buf);
    return NULL;
  }

  memcpy(date_buf, DAY_NAMES[tm->tm_wday], 3);
  memcpy(date_buf + 8, MONTH_NAMES[tm->tm_mon], 3);

  return date_buf;
}

#define LOG_WITH_LEVEL(level) \
  va_list ap; \
  if (fprintf(LOG_FILE, "%s\t", level) < 0) { \
    abort(); \
  } \
  va_start(ap, format); \
  if (vfprintf(LOG_FILE, format, ap) < 0) { \
    abort(); \
  } \
  if (fprintf(LOG_FILE, "\n") < 0) { \
    abort(); \
  } \
  va_end(ap);

void log_fatal(char * format, ...)
{
  if (LOG_FATAL) {
    LOG_WITH_LEVEL("FATAL")
  }
}

void log_warning(char * format, ...)
{
  if (LOG_WARN) {
    LOG_WITH_LEVEL("WARN")
  }
}

void log_error(char * format, ...)
{
  if (LOG_ERROR) {
    LOG_WITH_LEVEL("ERROR")
  }
}

void log_info(char * format, ...)
{
  if (LOG_INFO) {
    LOG_WITH_LEVEL("INFO")
  }
}

void log_debug(char * format, ...)
{
  if (LOG_DEBUG) {
    LOG_WITH_LEVEL("DEBUG")
  }
}

void log_trace(char * format, ...)
{
  if (LOG_TRACE) {
    LOG_WITH_LEVEL("TRACE")
  }
}
