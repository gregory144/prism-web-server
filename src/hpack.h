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

  size_t index;

  bool from_static_table;

  struct hpack_header_table_entry_t* prev;
  struct hpack_header_table_entry_t* next;

} hpack_header_table_entry_t;

typedef struct hpack_header_table_t {

  size_t length;

  hpack_header_table_entry_t* entries;

} hpack_header_table_t;

typedef struct hpack_reference_set_entry_t {

  hpack_header_table_entry_t* entry;

  struct hpack_reference_set_entry_t* next;

} hpack_reference_set_entry_t;

typedef struct hpack_reference_set_t {

  hpack_reference_set_entry_t* first;

} hpack_reference_set_t;

typedef struct hpack_headers_t {

  char* name;
  size_t name_length;

  char* value;
  size_t value_length;

  struct hpack_headers_t* next;

} hpack_headers_t;

typedef struct hpack_context_t {

  size_t header_table_size;
  hpack_header_table_t* header_table;

  hpack_reference_set_t* reference_set;

} hpack_context_t;

hpack_decode_quantity_result_t* hpack_decode_quantity(uint8_t* buf, size_t length, uint8_t offset); 

size_t hpack_encode_quantity(uint8_t* buf, size_t offset, size_t quantity); 

hpack_context_t* hpack_context_init(size_t header_table_size);

void hpack_adjust_header_table_size(hpack_context_t* context);

hpack_headers_t* hpack_decode(hpack_context_t* context, uint8_t* buf, size_t length);

hpack_encode_result_t* hpack_encode(hpack_context_t* context, hpack_headers_t* headers);

#endif
