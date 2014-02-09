/**
 *
 * Implements HPACK HTTP2 header encoding/decoding. See
 *
 * http://tools.ietf.org/html/draft-ietf-httpbis-header-compression-05
 */

#include <stdint.h>

#ifndef HPACK_H
#define HPACK_H 

int hpack_decode_int(char* buf, int length, uint8_t offset); 

#endif
