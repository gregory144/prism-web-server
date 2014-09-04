/**
 *
 * Implements HPACK HTTP2 header encoding/decoding. See
 *
 * http://tools.ietf.org/html/draft-ietf-httpbis-header-compression-05
 */

#ifndef HPACK_H
#define HPACK_H

#include <stdint.h>
#include <stdbool.h>

#include "circular_buffer.h"
#include "header_list.h"
#include "binary_buffer.h"

#define HEADER_TABLE_OVERHEAD 32

#define ESTIMATED_HEADER_NAME_SIZE 10
#define ESTIMATED_HEADER_VALUE_SIZE 20
#define ESTIMATED_HEADER_ENTRY_SIZE HEADER_TABLE_OVERHEAD + \
  ESTIMATED_HEADER_NAME_SIZE + ESTIMATED_HEADER_VALUE_SIZE

typedef struct {
  size_t num_bytes;
  size_t value;
} hpack_decode_quantity_result_t;

typedef struct {
  uint8_t * buf;
  size_t buf_length;
} hpack_encode_result_t;

typedef struct {

  char * name;
  size_t name_length;
  bool free_name;

  char * value;
  size_t value_length;
  bool free_value;

  size_t size_in_table;

  bool from_static_table;

} hpack_header_table_entry_t;

typedef struct {

  // maxiumum size in octets
  size_t max_size;

  // current size in octets as defined by
  // the spec
  size_t current_size;

  circular_buffer_t * header_table;

} hpack_context_t;

void hpack_decode_quantity(const uint8_t * const buf, const size_t length, const uint8_t offset,
                           hpack_decode_quantity_result_t * const result);

bool hpack_encode_quantity(binary_buffer_t * const buf, const uint8_t first_byte, const size_t bit_offset,
                           const size_t quantity);

hpack_context_t * hpack_context_init(const size_t header_table_size);

void hpack_context_free(hpack_context_t * const context);

void hpack_header_table_adjust_size(hpack_context_t * const context, size_t new_size);

header_list_t * hpack_decode(hpack_context_t * const context, const uint8_t * const buf, const size_t length);

binary_buffer_t * hpack_encode(hpack_context_t * const context, const header_list_t * const header_list,
                               binary_buffer_t * result);

#endif
