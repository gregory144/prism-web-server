#include <stdint.h>
#include <string.h>

#include "util.h"

#include "base64url.h"

/**
 * Maps base64url characters into their ascii equivalent.
 */
static uint8_t decoding_table[] = {
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,    // 0
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,    // 16
/*                                                                */
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,    // 32
/* 0   1   2   3   4   5   6   7   8   9               -          */
  52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, 62, -1, -1,    // 48
/*     A   B   C   D   E   F   G   H   I   J   K   L   M   N   O  */
  -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,    // 64
/* P   Q   R   S   T   U   V   W   X   Y   Z                   _  */
  15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, 63,    // 80
/*     a   b   c   d   e   f   g   h   i   j   k   l   m   n   o  */
  -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,    // 96
/* p   q   r   s   t   u   v   w   x   y   z                      */
  41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,    // 112
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

void base64url_decode(binary_buffer_t * buf, char * base64)
{
  unsigned char * in = (unsigned char *) base64;
  size_t in_length = strlen(base64);

  // base64 converts 3 octets into 4 encoded characters
  for (size_t i = 0; i < in_length; i += 4) {
    // d1, d2, d3 are the decoded octets
    //       d1              d2              d3
    // 0 0 0 0 0 0 0 0|0 0 0 0 0 0 0 0|0 0 0 0 0 0 0 0
    // 0 0 0 0 0 0|0 0 0 0 0 0|0 0 0 0 0 0|0 0 0 0 0 0
    //      e1          e2          e3         e4
    // e1, e2, e3, e4 are the encoded octets
    //
    // Text content     M               a             n
    // ASCII            77 (0x4d)       97 (0x61)     110 (0x6e)
    // Bit pattern      0 1 0 0 1 1 0 1 0 1 1 0 0 0 0 1 0 1 1 0 1 1 1 0
    // Index            19          22          5           46
    // Base64-encoded   T           W           F           u

    uint8_t sextet1 = decoding_table[in[i + 0]];
    uint8_t sextet2 = i + 1 < in_length ? decoding_table[in[i + 1]] : 0;
    uint8_t sextet3 = i + 2 < in_length ? decoding_table[in[i + 2]] : 0;
    uint8_t sextet4 = i + 3 < in_length ? decoding_table[in[i + 3]] : 0;

    uint32_t triple = (sextet1 << 3 * 6) + (sextet2 << 2 * 6)
                      + (sextet3 << 1 * 6) + (sextet4 << 0 * 6);

    // a single remaining encoded character is not possible
    // 2 remaining chars = 1 octet output
    // 3 remaining chars = 2 octets output
    // 4 remaining chars = 3 octets output
    // or more = 3 octets output
    size_t in_remaining = in_length - i;

    uint8_t octet1 = (triple >> 2 * 8) & 0xFF;
    binary_buffer_write_curr_index(buf, octet1);
    if (in_remaining >= 3) {
      uint8_t octet2 = (triple >> 1 * 8) & 0xFF;
      binary_buffer_write_curr_index(buf, octet2);
      if (in_remaining > 3) {
        uint8_t octet3 = (triple >> 0 * 8) & 0xFF;
        binary_buffer_write_curr_index(buf, octet3);
      }
    }
  }
}
