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
  { "accept-encoding", "" },
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

  context->header_table = malloc(sizeof(hpack_header_table_t));
  ASSERT_OR_RETURN_NULL(context->header_table);
  context->header_table->max_size = header_table_size;
  context->header_table->current_size = 0;
  context->header_table->entries = circular_buffer_init(header_table_size / ESTIMATED_HEADER_ENTRY_SIZE);

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

static void hpack_header_table_free(hpack_header_table_t * header_table)
{
  circular_buffer_free(header_table->entries, hpack_header_table_entry_free);
  free(header_table);
}

void hpack_context_free(const hpack_context_t * const context)
{
  hpack_header_table_free(context->header_table);
  free((void *)context);
}

static hpack_header_table_entry_t * hpack_header_table_get(const hpack_context_t * const context, const size_t index)
{
  if (index > 0 && index + 1 <= context->header_table->entries->length) {
    return circular_buffer_get(context->header_table->entries, index);
  }

  return NULL;
}

static void hpack_reference_set_add(const hpack_context_t * const context,
                                    hpack_header_table_entry_t * const header)
{
  UNUSED(context);
  header->in_refset = true;
}

static void hpack_reference_set_remove(hpack_header_table_entry_t * const entry)
{
  entry->in_refset = false;
}

static bool hpack_reference_set_contains(hpack_header_table_entry_t * const entry)
{
  return entry->in_refset;
}

static void hpack_reference_set_clear(const hpack_context_t * const context)
{
  circular_buffer_iter_t iter;
  circular_buffer_iterator_init(&iter, context->header_table->entries);

  while (circular_buffer_iterate(&iter)) {
    hpack_reference_set_remove(iter.value);
  }
}

static void hpack_header_table_evict(const hpack_context_t * const context)
{
  hpack_header_table_t * header_table = context->header_table;

  const size_t last_index = header_table->entries->length;

  if (last_index > 0) {
    hpack_header_table_entry_t * entry = hpack_header_table_get(context, last_index);

    if (entry) {
      header_table->current_size -= entry->size_in_table;
      hpack_header_table_entry_t * evicted = circular_buffer_evict(header_table->entries);
      hpack_header_table_entry_free(evicted);
    }
  }
}

void hpack_header_table_adjust_size(const hpack_context_t * const context, const size_t new_size)
{
  context->header_table->max_size = new_size;
  hpack_header_table_t * header_table = context->header_table;

  while (header_table->current_size > header_table->max_size) {
    hpack_header_table_evict(context);
  }
}

static void hpack_emit_header(const multimap_t * const headers, char * name,
                              size_t name_length, char * value, size_t value_length)
{

  if (LOG_TRACE) {
    log_trace("Emitting header: '%s' (%ld): '%s' (%ld)", name, name_length, value, value_length);
  }

  char * name_copy, * value_copy;
  size_t value_start = 0;
  size_t value_index;

  // there may be multiple values in this header
  // the values are separated by a zero-valued octet
  //
  // See https://tools.ietf.org/html/draft-ietf-httpbis-http2-10#section-8.1.3.3
  for (value_index = 0; value_index < value_length; value_index++) {
    // the last value is not terminated by a 0 octet
    if (value_index == value_length - 1 || value[value_index + 1] == '\0') {
      COPY_STRING(name_copy, name, name_length);
      COPY_STRING(value_copy, value + value_start, value_index + 1 - value_start);
      multimap_put((multimap_t * const) headers, name_copy, value_copy);

      value_start = value_index + 2;
    }
  }

}

static hpack_header_table_entry_t * hpack_header_table_add_existing_entry(
  const hpack_context_t * const context, hpack_header_table_entry_t * const header)
{

  hpack_header_table_t * header_table = context->header_table;

  size_t new_header_table_size = header_table->current_size +
                                 header->size_in_table;

  while (new_header_table_size > header_table->max_size) {
    // remove from the end of the table
    hpack_header_table_evict(context);

    new_header_table_size = header_table->current_size +
                            header->size_in_table;
  }

  // make sure it fits in the header table
  if (header->size_in_table <= header_table->max_size) {

    header->added_on_current_request = true;

    if (LOG_TRACE) log_trace("Adding to header table: '%s' (%ld): '%s' (%ld)",
                               header->name, header->name_length, header->value, header->value_length);

    context->header_table->current_size += header->size_in_table;
    circular_buffer_add(context->header_table->entries, header);

    // add to reference set
    hpack_reference_set_add(context, header);
  }

  return header;
}

static hpack_header_table_entry_t * hpack_header_table_add(const hpack_context_t * const context,
    char * name, size_t name_length, char * value, size_t value_length)
{
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

  return hpack_header_table_add_existing_entry(context, header);
}

static hpack_header_table_entry_t * hpack_static_table_get(const hpack_context_t * const context, const size_t index)
{
  size_t header_table_length = context->header_table->entries->length;

  if (index + 1 > header_table_length) {
    size_t static_table_index = index - header_table_length - 1;
    static_entry_t entry = static_table[static_table_index];
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
  const hpack_context_t * const context, const uint8_t * const buf, const size_t length,
  size_t * const current, string_and_length_t * const ret)
{
  UNUSED(context);
  ASSERT_OR_RETURN_FALSE(ret);
  bool first_bit = get_bit(buf + (*current), 0); // is it huffman encoded?
  hpack_decode_quantity_result_t key_name_result;
  hpack_decode_quantity(buf + (*current), length - (*current), 1, &key_name_result);
  *current += key_name_result.num_bytes;
  size_t key_name_length = key_name_result.value;

  if (LOG_TRACE) {
    log_trace("Decoding string literal length: %ld", key_name_length);
  }

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

static bool hpack_decode_literal_header(
  const hpack_context_t * const context, const multimap_t * const headers, const uint8_t * const buf,
  const size_t length, size_t * const current, const size_t bit_offset, const bool add_to_header_table)
{

  hpack_decode_quantity_result_t index_result;
  hpack_decode_quantity(buf + (*current), length - (*current), bit_offset, &index_result);
  size_t header_table_index = index_result.value;
  *current += index_result.num_bytes;

  if (LOG_TRACE) {
    log_trace("Adding literal header field: %ld, %ld", index_result.value, index_result.num_bytes);
  }

  char * key_name = NULL;
  size_t key_name_length = 0;

  if (header_table_index == 0) {

    // literal name
    string_and_length_t ret;

    if (hpack_decode_string_literal(context, buf, length, current, &ret)) {
      key_name = ret.value;
      key_name_length = ret.length;
    } else {
      log_error("Error decoding literal header: unable to decode literal name");
      return false;
    }

    if (LOG_TRACE) {
      log_trace("Literal name: '%s' (%ld)", key_name, key_name_length);
    }

  } else {

    // indexed name
    if (LOG_TRACE) {
      log_trace("getting from header table %ld", header_table_index);
    }

    hpack_header_table_entry_t * entry = hpack_header_table_get(context, header_table_index);

    if (!entry) {
      if (LOG_TRACE) {
        log_trace("getting from static table %ld", header_table_index);
      }

      entry = hpack_static_table_get(context, header_table_index);
    }

    if (!entry) {
      // TODO protocol error - invalid index
      log_error("Error decoding literal header with indexed name: invalid index (%d)", header_table_index);
      return false;
    }

    COPY_STRING(key_name, entry->name, entry->name_length);
    key_name_length = entry->name_length;

    if (LOG_TRACE) {
      log_trace("Indexed name: '%s' (%ld)", key_name, key_name_length);
    }

    if (entry->from_static_table) {
      free(entry);
    }

  }

  // literal value
  string_and_length_t ret;

  if (!hpack_decode_string_literal(context, buf, length, current, &ret)) {
    log_error("Error decoding literal header: unable to decode literal value");
    return false;
  }

  char * value = ret.value;
  size_t value_length = ret.length;

  if (LOG_TRACE) {
    log_trace("Emitting header literal value: %s (%ld), %s (%ld)", key_name, key_name_length, value, value_length);
  }

  if (add_to_header_table) {
    hpack_header_table_entry_t * header = hpack_header_table_add(context,
                                          key_name, key_name_length, value, value_length);
    hpack_emit_header(headers, header->name, header->name_length,
                      header->value, header->value_length);
  } else {
    hpack_emit_header(headers, key_name, key_name_length,
                      value, value_length);
    free(key_name);
    free(value);
  }

  return true;
}

static bool hpack_decode_indexed_header(
  const hpack_context_t * const context, const multimap_t * const headers, const uint8_t * const buf,
  const size_t length, size_t * const current)
{

  hpack_decode_quantity_result_t result;
  hpack_decode_quantity(buf + (*current), length - (*current), 1, &result);
  *current += result.num_bytes;
  size_t index = result.value;

  if (LOG_TRACE) {
    log_trace("Adding indexed header field: %ld", index);
  }

  if (LOG_TRACE) {
    log_trace("Header table size: %ld", context->header_table->entries->length);
  }

  if (index == 0) {

    // decoding error (see 4.2)
    log_error("Error decoding indexed header: invalid index (0)");
    return false;

  } else {

    // if the value is in the reference set - remove it from the reference set
    hpack_header_table_entry_t * entry = hpack_header_table_get(context, index);

    if (entry && hpack_reference_set_contains(entry)) {
      hpack_reference_set_remove(entry);
    } else {
      if (!entry) {
        entry = hpack_static_table_get(context, index);
      }

      if (!entry) {
        log_error("Error decoding indexed header: invalid index (%d)", index);
        return false;
      }

      hpack_header_table_add_existing_entry(context, entry);
      hpack_emit_header(headers, entry->name,
                        entry->name_length, entry->value, entry->value_length);

      if (LOG_TRACE) {
        log_trace("From index: %s: %s", entry->name, entry->value);
      }
    }

  }

  return true;
}

static bool hpack_decode_context_update(
  const hpack_context_t * const context, const uint8_t * const buf,
  const size_t length, size_t * const current, const bool fourth_bit)
{

  hpack_decode_quantity_result_t result;
  hpack_decode_quantity(buf + (*current), length - (*current), 4, &result);
  *current += result.num_bytes;
  size_t new_size = result.value;

  // 4.4 encoding context update
  if (fourth_bit == 0) {
    // empty ref set

    // low 4 bits must be 0
    if (new_size != 0) {
      // error!
      log_error("Unable to decode context update: low bits must be set to 0");
      return false;
    }

    hpack_reference_set_clear(context);

  } else {

    // adjust header table size
    hpack_header_table_adjust_size(context, new_size);

  }

  return true;

}

/**
 * Finds any cookie values and transforms them into a single value
 */
static void concatenate_cookie_fields(multimap_t * headers)
{
  char * name = "cookie";
  multimap_values_t * values = multimap_get(headers, name);

  if (values) {
    // First count the size of the final appended strings
    size_t length = 0;
    size_t num_crumbs = 0;
    multimap_values_t * curr = values;

    while (curr) {
      length += strlen(curr->value);
      curr = curr->next;
      num_crumbs++;
    }

    size_t total_length = length + ((num_crumbs - 1) * 2);

    // Append all the values together
    char * single_cookie = malloc(sizeof(char) * (total_length + 1));
    size_t total_index = 0;
    size_t curr_index;
    curr = values;

    while (curr) {
      char * value = curr->value;

      for (curr_index = 0; curr_index < strlen(value); curr_index++) {
        single_cookie[total_index++] = value[curr_index];
      }

      curr = curr->next;

      if (curr) {
        // seprated by "; "
        single_cookie[total_index++] = ';';
        single_cookie[total_index++] = ' ';
      }
    }

    single_cookie[total_index] = '\0';
    // remove the old cookie values
    multimap_remove(headers, name, free, free);
    // add the single concatenated value
    multimap_put(headers, strdup(name), single_cookie);
  }
}

multimap_t * hpack_decode(const hpack_context_t * const context, const uint8_t * const buf, const size_t length)
{

  size_t current = 0;
  multimap_t * headers = multimap_init_with_string_keys();

  if (!headers) {
    if (LOG_ERROR) {
      log_error("Could not allocate memory for headers");
    }

    return NULL;
  }

  if (LOG_TRACE) {
    log_trace("Decompressing headers: %ld, %ld", current, length);
  }

  while (current < length) {
    uint8_t first_bit = get_bits8(buf, current, 0x80);
    uint8_t second_bit = get_bits8(buf, current, 0x40);
    uint8_t third_bit = get_bits8(buf, current, 0x20);
    uint8_t fourth_bit = get_bits8(buf, current, 0x10);

    bool success = false;

    if (first_bit) {
      // indexed header field (4.2)
      success = hpack_decode_indexed_header(context, headers, buf, length, &current);
    } else if (second_bit) {
      // literal header field with incremental indexing (4.3.1)
      success = hpack_decode_literal_header(context, headers, buf, length, &current, 2, true);
    } else if (third_bit) {
      success = hpack_decode_context_update(context, buf, length, &current, fourth_bit);
    } else if (fourth_bit) {
      // literal header field never indexed 4.3.3
      success = hpack_decode_literal_header(context, headers, buf, length, &current, 4, false);
    } else {
      // literal header field without indexing (4.3.2)
      success = hpack_decode_literal_header(context, headers, buf, length, &current, 4, false);
    }

    if (!success) {
      return NULL;
    }

  }

  // does this need to go below the emissionof reference set headers?
  concatenate_cookie_fields(headers);

  // emit reference set headers
  if (LOG_TRACE) {
    log_trace("Emitting from ref set");
  }

  circular_buffer_iter_t iter;
  circular_buffer_iterator_init(&iter, context->header_table->entries);

  while (circular_buffer_iterate(&iter)) {
    hpack_header_table_entry_t * entry = iter.value;

    if (!entry->added_on_current_request && entry->in_refset) {
      hpack_emit_header(headers, entry->name,
                        entry->name_length, entry->value, entry->value_length);
    }

    entry->added_on_current_request = false;
  }

  return headers;
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
binary_buffer_t * hpack_encode(const hpack_context_t * const context, const multimap_t * const headers,
                               binary_buffer_t * result)
{
  UNUSED(context);

  ASSERT_OR_RETURN_NULL(binary_buffer_init(result, 512));

  multimap_iter_t iter;
  multimap_iterator_init(&iter, (multimap_t *) headers);

  while (multimap_iterate(&iter)) {
    char * name = iter.key;
    size_t name_length = strlen(name);
    char * value = iter.value;
    size_t value_length = strlen(value);

    if (LOG_TRACE) {
      log_trace("Encoding Reponse Header: %s (%ld): %s (%ld)", name, name_length, value, value_length);
    }

    // 4.3.2 Literal Header Field without Indexing - New Name
    // First byte = all zeros
    ASSERT_OR_RETURN_FALSE(binary_buffer_write_curr_index(result, 0x00));

    ASSERT_OR_RETURN_FALSE(hpack_encode_string_literal(result, name, name_length));
    ASSERT_OR_RETURN_FALSE(hpack_encode_string_literal(result, value, value_length));
  }

  if (LOG_TRACE) {
    log_trace("Encoded headers into %ld bytes", binary_buffer_size(result));
  }

  return result;
}

