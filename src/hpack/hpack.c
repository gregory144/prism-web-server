#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <math.h>

#include "hpack.h"
#include "../huffman/huffman.h"
#include "../util/util.h"

typedef struct static_entry_t {
  char * name;
  char * value;
} static_entry_t;

const static_entry_t static_table[] = {
  { ":authority", "" },
  { ":method", "GET" },
  { ":method", "POST" },
  { ":path", "/" },
  { ":path", "/index.html" },
  { ":scheme", "http" },
  { ":scheme", "https" },
  { ":status", "200" },
  { ":status", "204" },
  { ":status", "206" },
  { ":status", "304" },
  { ":status", "400" },
  { ":status", "404" },
  { ":status", "500" },
  { "accept-charset", "" },
  { "accept-encoding", "gzip, deflate" },
  { "accept-language", "" },
  { "accept-ranges", "" },
  { "accept", "" },
  { "access-control-allow-origin", "" },
  { "age", "" },
  { "allow", "" },
  { "authorization", "" },
  { "cache-control", "" },
  { "content-disposition", "" },
  { "content-encoding", "" },
  { "content-language", "" },
  { "content-length", "" },
  { "content-location", "" },
  { "content-range", "" },
  { "content-type", "" },
  { "cookie", "" },
  { "date", "" },
  { "etag", "" },
  { "expect", "" },
  { "expires", "" },
  { "from", "" },
  { "host", "" },
  { "if-match", "" },
  { "if-modified-since", "" },
  { "if-none-match", "" },
  { "if-range", "" },
  { "if-unmodified-since", "" },
  { "last-modified", "" },
  { "link", "" },
  { "location", "" },
  { "max-forwards", "" },
  { "proxy-authenticate", "" },
  { "proxy-authorization", "" },
  { "range", "" },
  { "referer", "" },
  { "refresh", "" },
  { "retry-after", "" },
  { "server", "" },
  { "set-cookie", "" },
  { "strict-transport-security", "" },
  { "transfer-encoding", "" },
  { "user-agent", "" },
  { "vary", "" },
  { "via", "" },
  { "www-authenticate", "" },
};

const size_t static_table_length = sizeof(static_table) / sizeof(static_entry_t);

void hpack_decode_quantity(const uint8_t * const buf, const size_t length, const uint8_t offset,
                           hpack_decode_quantity_result_t * const result)
{
  const size_t prefix_length = 8 - offset;
  const uint8_t limit = (1 << prefix_length) - 1; // 2^prefix_length - 1
  size_t i = 0;

  if (prefix_length != 0) {
    i = buf[0] & limit;
  }

  size_t index = 1;

  if (i == limit) {
    unsigned int m = 0;
    uint8_t next = buf[index];

    while (index < length) {
      i += (next & 127) << m;
      m += 7;

      if (next < 128) {
        break;
      }

      next = buf[++index];
    }

    index++;
  }

  result->num_bytes = index;
  result->value = i;
}

/**
 *
 * Encodes the given quantity as a bitstring in the given buffer.
 *
 * From the spec:
 * If I < 2^N - 1, encode I on N bits
 * Else
 *     encode 2^N - 1 on N bits
 *     I = I - (2^N - 1)
 *     While I >= 128
 *          Encode (I % 128 + 128) on 8 bits
 *          I = I / 128
 *     encode (I) on 8 bits
 */
bool hpack_encode_quantity(binary_buffer_t * const buf, const uint8_t first_byte, const size_t bit_offset,
                           const size_t quantity)
{
  size_t i = (size_t) quantity;
  uint8_t n = 8 - bit_offset;
  uint8_t p = (1 << n) - 1; // 2^n - 1

  if (i < p) {
    ASSERT_OR_RETURN_FALSE(binary_buffer_write_curr_index(buf, first_byte | i));
  } else {
    ASSERT_OR_RETURN_FALSE(binary_buffer_write_curr_index(buf, first_byte | p));
    i -= p;

    while (i >= 128) {
      ASSERT_OR_RETURN_FALSE(binary_buffer_write_curr_index(buf, (i % 128) + 128));
      i /= 128;
    }

    ASSERT_OR_RETURN_FALSE(binary_buffer_write_curr_index(buf, i));
  }

  return true;
}

hpack_context_t * hpack_context_init(const size_t header_table_size)
{
  hpack_context_t * context = malloc(sizeof(hpack_context_t));
  ASSERT_OR_RETURN_NULL(context);

  context->max_size = header_table_size;
  context->current_size = 0;
  context->header_table = circular_buffer_init(header_table_size / ESTIMATED_HEADER_ENTRY_SIZE);

  return context;
}

static void hpack_header_table_entry_free(void * entry)
{
  hpack_header_table_entry_t * header = entry;

  if (!header->from_static_table) {
    free(header->name);
    free(header->value);
  }

  free(header);
}

void hpack_context_free(hpack_context_t * const context)
{
  circular_buffer_free(context->header_table, hpack_header_table_entry_free);

  free(context);
}

static hpack_header_table_entry_t * hpack_header_table_get(hpack_context_t * const context, const size_t index)
{
  log_trace("Getting from header table with adjusted index: %ld", index);

  if (index > 0 && index <= context->header_table->length) {
    return circular_buffer_get(context->header_table, index);
  }

  return NULL;
}

static void hpack_header_table_evict(hpack_context_t * const context)
{
  const size_t last_index = context->header_table->length;

  if (last_index > 0) {
    hpack_header_table_entry_t * entry = circular_buffer_get(context->header_table, last_index);

    if (entry) {
      context->current_size -= entry->size_in_table;
      hpack_header_table_entry_t * evicted = circular_buffer_evict(context->header_table);
      hpack_header_table_entry_free(evicted);
    }
  }
}

void hpack_header_table_adjust_size(hpack_context_t * const context, const size_t new_size)
{
  context->max_size = new_size;

  while (context->current_size > context->max_size) {
    hpack_header_table_evict(context);
  }
}

static hpack_header_table_entry_t * hpack_header_table_add(hpack_context_t * const context,
    char * name, size_t name_length, char * value, size_t value_length)
{
  // create the new header table entry
  hpack_header_table_entry_t * const header = malloc(sizeof(hpack_header_table_entry_t));
  ASSERT_OR_RETURN_NULL(header);
  header->from_static_table = false;
  header->name = name;
  header->name_length = name_length;
  header->value = value;
  header->value_length = value_length;

  // add an extra 32 octets - see
  // http://tools.ietf.org/html/draft-ietf-httpbis-header-compression-05#section-3.3.1
  header->size_in_table = name_length + value_length + HEADER_TABLE_OVERHEAD;

  // insert the entry into the table
  size_t new_header_table_size = context->current_size + header->size_in_table;

  // make sure there is room in the table before adding
  while (new_header_table_size > context->max_size) {
    // remove from the end of the table
    hpack_header_table_evict(context);

    new_header_table_size = context->current_size + header->size_in_table;
  }

  // make sure it fits in the header table before adding it
  if (header->size_in_table <= context->max_size) {

    log_trace("Adding to header table: '%s' (%ld): '%s' (%ld)",
              header->name, header->name_length, header->value, header->value_length);

    context->current_size += header->size_in_table;
    circular_buffer_add(context->header_table, header);
  }

  return header;
}

static hpack_header_table_entry_t * hpack_static_table_get(const size_t index)
{
  if (index > 0 && index - 1 < static_table_length) {
    static_entry_t entry = static_table[index - 1];
    hpack_header_table_entry_t * header = malloc(sizeof(hpack_header_table_entry_t));
    ASSERT_OR_RETURN_NULL(header);
    size_t name_length = strlen(entry.name);
    size_t value_length = strlen(entry.value);
    header->from_static_table = true;
    header->name = entry.name;
    header->name_length = name_length;
    header->value = entry.value;
    header->value_length = value_length;

    // add an extra 32 octets - see
    // http://tools.ietf.org/html/draft-ietf-httpbis-header-compression-05#section-3.3.1
    header->size_in_table = name_length + value_length + HEADER_TABLE_OVERHEAD;

    // TODO - this will need to be free'd by caller, but the caller won't
    // know whether it can - because we also return non-freeable entries below
    return header;
  }

  return NULL;
}

static bool hpack_decode_string_literal(
  hpack_context_t * const context, const uint8_t * const buf, const size_t length,
  size_t * const current, string_and_length_t * const ret)
{
  UNUSED(context);
  ASSERT_OR_RETURN_FALSE(ret);
  bool first_bit = get_bit(buf + (*current), 0); // is it huffman encoded?
  hpack_decode_quantity_result_t key_name_result;
  hpack_decode_quantity(buf + (*current), length - (*current), 1, &key_name_result);
  *current += key_name_result.num_bytes;
  size_t key_name_length = key_name_result.value;

  log_trace("Decoding string literal length: %ld", key_name_length);

  char * key_name;

  if (first_bit) {
    huffman_result_t huffman_result;
    ASSERT_OR_RETURN_FALSE(huffman_decode(buf + (*current), key_name_length, &huffman_result));
    *current += key_name_length;
    key_name_length = huffman_result.length;
    COPY_STRING(key_name, huffman_result.value, key_name_length);
    free(huffman_result.value);
  } else {
    COPY_STRING(key_name, buf + (*current), key_name_length);
    *current += key_name_length;
  }

  ret->value = key_name;
  ret->length = key_name_length;
  return true;
}

static hpack_header_table_entry_t * hpack_table_get(hpack_context_t * const context, const size_t index)
{
  hpack_header_table_entry_t * entry;

  if (index < static_table_length) {
    entry = hpack_static_table_get(index);
  } else {
    size_t adjusted_index = index - static_table_length;
    entry = hpack_header_table_get(context, adjusted_index);
  }

  if (entry) {
    log_trace("From index: %s: %s", entry->name, entry->value);
  }

  return entry;
}

/**
 *
 * A _literal representation_ that is _not added_ to the header table
 * entails the following action:
 * The header field is added to the decoded header list.
 *
 * A _literal representation_ that is _added_ to the header table
 * entails the following actions:
 * The header field is added to the decoded header list.
 * The header field is inserted at the beginning of the header table.
 */
static bool hpack_decode_literal_header(
  hpack_context_t * const context, header_list_t * const header_list, const uint8_t * const buf,
  const size_t length, size_t * const current, const size_t bit_offset, const bool add_to_header_table)
{

  hpack_decode_quantity_result_t index_result;
  hpack_decode_quantity(buf + (*current), length - (*current), bit_offset, &index_result);
  size_t header_table_index = index_result.value;
  *current += index_result.num_bytes;

  log_trace("Adding literal header field: %ld, %ld", index_result.value, index_result.num_bytes);

  char * key_name = NULL;
  size_t key_name_length = 0;
  bool free_name = false;

  if (header_table_index == 0) {

    // Literal Header Field with Incremental Indexing - New Name
    string_and_length_t ret;

    if (hpack_decode_string_literal(context, buf, length, current, &ret)) {
      key_name = ret.value;
      key_name_length = ret.length;
      free_name = true;
    } else {
      log_error("Error decoding literal header: unable to decode literal name");
      return false;
    }

    log_trace("Literal name: '%s' (%ld)", key_name, key_name_length);

  } else {

    // Literal Header Field with Incremental Indexing - Indexed Name
    hpack_header_table_entry_t * entry = hpack_table_get(context, header_table_index);

    if (!entry) {
      // TODO protocol error - invalid index
      log_error("Error decoding literal header with indexed name: invalid index (%d)", header_table_index);
      return false;
    }

    key_name = entry->name;
    key_name_length = entry->name_length;

    if (entry->from_static_table) {
      free(entry);
    }

  }

  // literal value
  string_and_length_t ret;

  if (!hpack_decode_string_literal(context, buf, length, current, &ret)) {
    log_error("Error decoding literal header: unable to decode literal value");

    if (key_name) {
      free(key_name);
    }

    return false;
  }

  char * value = ret.value;
  size_t value_length = ret.length;

  log_trace("Emitting header literal value: %s (%ld), %s (%ld)", key_name, key_name_length, value, value_length);

  if (add_to_header_table) {
    hpack_header_table_add(context, key_name, key_name_length, value, value_length);
    header_list_push(header_list, key_name, key_name_length, free_name, value, value_length, false);
  } else {
    header_list_push(header_list, key_name, key_name_length, free_name, value, value_length, true);
  }

  return true;
}

/**
 *
 * From 4.2:
 *
 * An _indexed representation_ entails the following actions:
 *
 * The header field corresponding to the referenced entry in either
 * the static table or header table is added to the decoded header
 * list.
 */
static bool hpack_decode_indexed_header(
  hpack_context_t * const context, header_list_t * const header_list, const uint8_t * const buf,
  const size_t length, size_t * const current)
{

  hpack_decode_quantity_result_t result;
  hpack_decode_quantity(buf + (*current), length - (*current), 1, &result);
  *current += result.num_bytes;
  size_t index = result.value;

  if (index == 0) {

    // decoding error (see 4.2)
    log_error("Error decoding indexed header: invalid index (0)");
    return false;

  } else {

    hpack_header_table_entry_t * entry = hpack_table_get(context, index);

    if (!entry) {
      log_error("Error decoding indexed header: invalid index (%ld)", index);
      return false;
    }

    header_list_push(header_list, entry->name, entry->name_length, false, entry->value, entry->value_length, false);

    if (entry->from_static_table) {
      free(entry);
    }

  }

  return true;
}

static bool hpack_decode_context_update(
  hpack_context_t * const context, const uint8_t * const buf,
  const size_t length, size_t * const current)
{

  hpack_decode_quantity_result_t result;
  hpack_decode_quantity(buf + (*current), length - (*current), 4, &result);
  *current += result.num_bytes;
  size_t new_size = result.value;

  // adjust header table size
  hpack_header_table_adjust_size(context, new_size);

  return true;

}

header_list_t * hpack_decode(hpack_context_t * const context, const uint8_t * const buf, const size_t length)
{

  size_t current = 0;
  header_list_t * header_list = header_list_init(NULL);
  ASSERT_OR_RETURN_NULL(header_list);

  log_trace("Decompressing headers: %ld, %ld", current, length);

  while (current < length) {
    uint8_t first_bit = get_bits8(buf + current, 0x80);
    uint8_t second_bit = get_bits8(buf + current, 0x40);
    uint8_t third_bit = get_bits8(buf + current, 0x20);

    bool success = false;

    if (first_bit) {
      // Indexed Header Field Representation (7.1)
      success = hpack_decode_indexed_header(context, header_list, buf, length, &current);
    } else if (second_bit) {
      // Literal Header Field with Incremental Indexing (7.2.1)
      success = hpack_decode_literal_header(context, header_list, buf, length, &current, 2, true);
    } else if (third_bit) {
      // Header Table Size Update
      success = hpack_decode_context_update(context, buf, length, &current);
    } else {
      // Literal Header Field without Indexing (7.2.2)
      // Literal Header Field never Indexed (7.2.3)
      success = hpack_decode_literal_header(context, header_list, buf, length, &current, 4, false);
    }

    if (!success) {
      header_list_free(header_list);
      return NULL;
    }

  }

  return header_list;
}

static bool hpack_encode_string_literal(binary_buffer_t * const encoded, char * name, size_t name_length)
{
  uint8_t first_byte = 0x80; // set huffman encoded bit
  huffman_result_t encoded_name;
  ASSERT_OR_RETURN_FALSE(huffman_encode(name, name_length, &encoded_name));
  ASSERT_OR_RETURN_FALSE(hpack_encode_quantity(encoded, first_byte, 1, encoded_name.length));
  ASSERT_OR_RETURN_FALSE(binary_buffer_write(encoded, encoded_name.value, encoded_name.length));
  free(encoded_name.value);

  return true;
}

// naive hpack encoding - never add to the header table
binary_buffer_t * hpack_encode(hpack_context_t * const context, const header_list_t * const header_list,
                               binary_buffer_t * result)
{
  UNUSED(context);

  ASSERT_OR_RETURN_NULL(binary_buffer_init(result, 512));

  header_list_iter_t iter;
  header_list_iterator_init(&iter, (header_list_t *) header_list);

  while (header_list_iterate(&iter)) {
    char * name = iter.field->name;
    size_t name_length = iter.field->name_length;
    char * value = iter.field->value;
    size_t value_length = iter.field->value_length;

    log_trace("Encoding Reponse Header: %s (%ld): %s (%ld)", name, name_length, value, value_length);

    // 4.3.2 Literal Header Field without Indexing - New Name
    // First byte = all zeros
    ASSERT_OR_RETURN_FALSE(binary_buffer_write_curr_index(result, 0x00));

    ASSERT_OR_RETURN_FALSE(hpack_encode_string_literal(result, name, name_length));
    ASSERT_OR_RETURN_FALSE(hpack_encode_string_literal(result, value, value_length));
  }

  log_trace("Encoded headers into %ld bytes", binary_buffer_size(result));

  return result;
}

