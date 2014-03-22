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
#include "multimap.h"

#define HEADER_TABLE_OVERHEAD 32

#define ESTIMATED_HEADER_NAME_SIZE 10
#define ESTIMATED_HEADER_VALUE_SIZE 20
#define ESTIMATED_HEADER_ENTRY_SIZE HEADER_TABLE_OVERHEAD + \
  ESTIMATED_HEADER_NAME_SIZE + ESTIMATED_HEADER_VALUE_SIZE

typedef struct hpack_decode_quantity_result_t {
  size_t num_bytes;
  size_t value;
} hpack_decode_quantity_result_t;

typedef struct hpack_encode_result_t {
  uint8_t* buf;
  size_t buf_length;
} hpack_encode_result_t;

typedef struct hpack_header_table_entry_t {

  char* name;
  size_t name_length;

  char* value;
  size_t value_length;

  size_t size_in_table;

  // TODO can these flags be moved to a bitset?
  bool from_static_table;

  bool in_refset; 

  bool added_on_current_request;

} hpack_header_table_entry_t;

typedef struct hpack_header_table_t {

  // maxiumum size in octets
  size_t max_size;

  // current size in octets as defined by
  // the spec
  size_t current_size;

  circular_buffer_t* entries;

} hpack_header_table_t;

typedef struct hpack_context_t {

  hpack_header_table_t* header_table;

} hpack_context_t;

hpack_decode_quantity_result_t* hpack_decode_quantity(uint8_t* buf, size_t length, uint8_t offset); 

size_t hpack_encode_quantity(uint8_t* buf, size_t offset, size_t quantity); 

hpack_context_t* hpack_context_init(size_t header_table_size);

void hpack_context_free(hpack_context_t* context);

void hpack_header_table_adjust_size(hpack_context_t* context, size_t new_size);

multimap_t* hpack_decode(hpack_context_t* context, uint8_t* buf, size_t length);

hpack_encode_result_t* hpack_encode(hpack_context_t* context, multimap_t* headers);

#endif
