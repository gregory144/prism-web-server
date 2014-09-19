#ifndef BASE64URL_H
#define BASE64URL_H

#include "binary_buffer.h"

/**
 * Takes a base64url encoded string and decodes it.
 *
 * Base64url is described here:
 * https://tools.ietf.org/html/rfc4648#section-5
 *
 * It is "normal" base64 but with the last 2 characters
 * replaced with '-' and '_'.
 *
 * The buf parameter should point to an initialized binary
 * buffer.
 */
void base64url_decode(binary_buffer_t * buf, char * base64);

#endif
