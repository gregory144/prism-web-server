#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "util.h"

/**
 *
 * Round this value to the next highest power of 2
 *
 * See http://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2
 *
 */
size_t roundup_to_power_of_2(size_t v)
{
  if (v == 1) {
    return 1;
  }

  // TODO - does this work for values greater than 2^32?

  v--;
  v |= v >> 1;
  v |= v >> 2;
  v |= v >> 4;
  v |= v >> 8;
  v |= v >> 16;
  if (sizeof(size_t) == 8) { // for 64 bit arch
    v |= v >> 32;
  }
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
    free(date_buf);
    return NULL;
  }

  memcpy(date_buf, DAY_NAMES[tm->tm_wday], 3);
  memcpy(date_buf + 8, MONTH_NAMES[tm->tm_mon], 3);

  return date_buf;
}

/*@null@*/ char * current_time_with_nanoseconds(char * date_buf, size_t buf_len)
{
  if (date_buf == NULL) {
    date_buf = malloc(sizeof(char) * buf_len);
    buf_len = TIME_WITH_MS_LEN + 1;
  }

  ASSERT_OR_RETURN_NULL(date_buf);

  time_t nowtime;
  struct tm * nowtm;
  char tmbuf[64];

  struct timespec ts;
  if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
    // failed to get time
    abort();
  }

  nowtime = ts.tv_sec;
  nowtm = localtime(&nowtime);

  int written = strftime(date_buf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", nowtm);
  snprintf(date_buf + written, buf_len - written, ".%.9ld", ts.tv_nsec);

  return date_buf;
}

