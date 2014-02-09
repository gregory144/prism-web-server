#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <math.h>

#include "hpack.h"

int hpack_decode_int(char* buf, int length, uint8_t offset) {
  size_t prefix_length = 8 - offset;
  uint8_t limit = pow(2, prefix_length) - 1;
  unsigned long i = 0;
  if (prefix_length != 0) {
    i = buf[0] & limit;
  }

  if (i == limit) {
    unsigned int m = 0;
    size_t index = 1;
    uint8_t next = buf[index];
    while (index < length) {
      i += ((next & 127) << m);
      m += 7;

      if (next < 128) {
        break;
      }
      
      next = buf[++index];
    }
  }

  return i;
}

