#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <math.h>

#include "hpack.h"
#include "huffman.h"
#include "util.h"

typedef struct static_entry_t {
  char* name;
  char* value;
} static_entry_t;

static_entry_t static_table[] = {
  { ":authority",                   "" },
  { ":method",                      "GET" },
  { ":method",                      "POST" },
  { ":path",                        "/" },
  { ":path",                        "/index.html" },
  { ":scheme",                      "http" },
  { ":scheme",                      "https" },
  { ":status",                      "200" },
  { ":status",                      "500" },
  { ":status",                      "404" },
  { ":status",                      "403" },
  { ":status",                      "400" },
  { ":status",                      "401" },
  { ":accept-charset",              "" },
  { ":accept-encoding",             "" },
  { ":accept-language",             "" },
  { ":accept-ranges",               "" },
  { ":accept",                      "" },
  { ":access-control-allow-origin", "" },
  { ":age",                         "" },
  { ":allow",                       "" },
  { ":authorization",               "" },
  { ":cache-control",               "" },
  { ":content-disposition",         "" },
  { ":content-encoding",            "" },
  { ":content-language",            "" },
  { ":content-length",              "" },
  { ":content-location",            "" },
  { ":content-range",               "" },
  { ":content-type",                "" },
  { ":cookie",                      "" },
  { ":date",                        "" },
  { ":etag",                        "" },
  { ":expect",                      "" },
  { ":expires",                     "" },
  { ":from",                        "" },
  { ":host",                        "" },
  { ":if-match",                    "" },
  { ":if-modified-since",           "" },
  { ":if-none-match",               "" },
  { ":if-range",                    "" },
  { ":if-unmodified-since",         "" },
  { ":last-modified",               "" },
  { ":link",                        "" },
  { ":location",                    "" },
  { ":max-forwards",                "" },
  { ":proxy-authenticate",          "" },
  { ":proxy-authorization",         "" },
  { ":range",                       "" },
  { ":referer",                     "" },
  { ":refresh",                     "" },
  { ":retry-after",                 "" },
  { ":server",                      "" },
  { ":set-cookie",                  "" },
  { ":strict-transport-security",   "" },
  { ":transfer-encoding",           "" },
  { ":user-agent",                  "" },
  { ":vary",                        "" },
  { ":via",                         "" },
  { ":www-authenticate",            "" }
};

// TODO - we need to be able to return how many bytes were read
hpack_decode_quantity_result_t* hpack_decode_quantity(char* buf, size_t length, uint8_t offset) {
  size_t prefix_length = 8 - offset;
  uint8_t limit = pow(2, prefix_length) - 1;
  size_t i = 0;
  if (prefix_length != 0) {
    i = buf[0] & limit;
  }

  size_t index = 1;
  if (i == limit) {
    unsigned int m = 0;
    uint8_t next = buf[index];
    while (index < length) {
      i += ((next & 127) << m);
      m += 7;

      if (next < 128) {
        break;
      }
      
      next = buf[++index];
    }
    index++;
  }

  hpack_decode_quantity_result_t* result = malloc(sizeof(hpack_decode_quantity_result_t));
  result->num_bytes = index;
  result->value = i;
  return result;
}

/**
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
void hpack_encode_quantity(char* buf, size_t offset, size_t quantity) {
  //uint8_t limit = pow(2, prefix_length) - 1;
  // TODO
  uint8_t n = 8; // for now
  fprintf(stderr, "quantity: %ld\n", quantity);
  buf[offset/8]  = quantity;
}

hpack_context_t* hpack_context_init(size_t header_table_size) {
  hpack_context_t* context = malloc(sizeof(hpack_context_t));
  context->header_table_size = header_table_size;
  context->reference_set = malloc(sizeof(hpack_reference_set_t));

  context->header_table = malloc(sizeof(hpack_header_table_t));
  context->header_table->length = 0;
  context->header_table->entries = NULL;

  return context;
}

void hpack_adjust_header_table_size(hpack_context_t* context) {
  // TODO
}

hpack_headers_t* hpack_emit_header(hpack_headers_t* headers, char* name,
    size_t name_length, char* value, size_t value_length) {
  hpack_headers_t* new_header = malloc(sizeof(hpack_headers_t));
  new_header->name = name;
  new_header->name_length = name_length;
  new_header->value = value;
  new_header->value_length = value_length;
  new_header->next = headers;

//  hpack_headers_t* curr = new_header;
//  while (curr) {
//    fprintf(stderr, "EMITTED: %s: %s\n", curr->name, curr->value);
//    curr = curr->next;
//  }

  return new_header;
}

hpack_header_table_entry_t* hpack_header_table_add_existing_entry(hpack_context_t* context,
    hpack_header_table_entry_t* header) {
  header->from_static_table = false;
  if (context->header_table->entries) {
    context->header_table->entries->prev = header;
  }
  header->next = context->header_table->entries;
  context->header_table->entries = header;
  context->header_table->length++;

  return header;
}

hpack_header_table_entry_t* hpack_header_table_add(hpack_context_t* context,
    char* name, size_t name_length, char* value, size_t value_length) {
  // TODO - remove from the end if necessary
  hpack_header_table_entry_t* header = malloc(sizeof(hpack_header_table_entry_t));
  header->from_static_table = false;
  header->name = name;
  header->name_length = name_length;
  header->value = value;
  header->value_length = value_length;
  header->index = context->header_table->length;

  return hpack_header_table_add_existing_entry(context, header);
}

hpack_header_table_entry_t* hpack_header_table_get(hpack_context_t* context, size_t index) {
  size_t header_table_length = context->header_table->length;
  if (index + 1 > header_table_length) {
    size_t static_table_index = index - header_table_length - 1;
    static_entry_t entry = static_table[static_table_index];
    hpack_header_table_entry_t* header = malloc(sizeof(hpack_header_table_entry_t));
    header->from_static_table = true;
    header->name = entry.name;
    header->name_length = strlen(entry.name);
    header->value = entry.value;
    header->value_length = strlen(entry.value);
    // this will need to be free'd by caller
    return header;
  } else {
    hpack_header_table_entry_t* iter = context->header_table->entries;
    while (iter) {
      if (iter->index == index) {
        return iter;
      }
    }
  }
  return NULL;
}

void hpack_reference_set_clear(hpack_context_t* context) {
  // TODO - free entries
  context->reference_set->first = NULL;
}

void hpack_reference_set_remove(hpack_context_t* context, size_t index) {
  hpack_reference_set_entry_t* iter = context->reference_set->first;
  hpack_reference_set_entry_t* prev = NULL;
  for (; iter; iter = iter->next) {
    if (iter->entry->index == index) {
      if (!prev) {
        context->reference_set->first = iter->next;
      } else {
        prev->next = iter->next;
      }
      free(iter);
    }
    prev = iter;
  }
}

bool hpack_reference_set_contains(hpack_context_t* context, size_t index) {
  hpack_reference_set_entry_t* iter = context->reference_set->first;
  for (; iter; iter = iter->next) {
    if (iter->entry->index == index) {
      return true;
    }
  }
  return false;
}

hpack_headers_t* hpack_decode(hpack_context_t* context, char* buf, size_t length) {
  size_t current = 0;
  // get current set of headers from reference set
  hpack_headers_t* headers = NULL;
  fprintf(stderr, "Decompressing headers: %ld, %ld\n", current, length);
  while (current < length) {
    // get first bit
    bool first_bit = get_bit(buf + current, 0);
    bool second_bit = get_bit(buf + current, 1);
    fprintf(stderr, "First bit: %d\n", first_bit);
    fprintf(stderr, "Second bit: %d\n", second_bit);
    if (!first_bit && second_bit) {
      // literal header field without indexing (4.3.1)
      hpack_decode_quantity_result_t* result = hpack_decode_quantity(buf + current, length - current, 2);
      current += result->num_bytes;
      fprintf(stderr, "Adding literal header field without indexing: %d, %ld, %ld\n", (buf + current)[0], result->value, result->num_bytes);
      char* key_name = NULL;
      size_t key_name_length = 0;
      if (index == 0) {
        // literal name
        fprintf(stderr, "Unhandled literal name\n");
      } else {
        hpack_header_table_entry_t* entry = hpack_header_table_get(context, result->value);
        key_name = entry->name;
        key_name_length = entry->name_length;
        fprintf(stderr, "Emitting header: %s\n", entry->name);
      }
      // literal value
      free(result);
      bool first_bit = get_bit(buf + current, 0);
      result = hpack_decode_quantity(buf + current, length - current, 1);
      current += result->num_bytes;
      size_t value_length = result->value;
      free(result);
      char* value = NULL;
      if (first_bit) {
        value = huffman_decode(buf + current, value_length);
      } else {
        value = malloc(value_length + 1);
        strncpy(value, buf + current, value_length);
        value[value_length] = '\0';
      }
      fprintf(stderr, "Emitting header literal value: %s, %s\n", key_name, value);
      headers = hpack_emit_header(headers, key_name, key_name_length, value, value_length);
    } else if (!first_bit && !second_bit) {
      // literal header field with incremental indexing (4.3.2)
      hpack_decode_quantity_result_t* result = hpack_decode_quantity(buf + current, length - current, 2);
      current += result->num_bytes;
      fprintf(stderr, "Adding literal header with incremental indexing: %d, %ld, num bytes: %ld\n", buf[0], result->value, result->num_bytes);
      char* key_name = "";
      size_t key_name_length = 0;
      if (result->value == 0) {
        // literal name
        fprintf(stderr, "Unhandled literal name\n");
      } else {
        hpack_header_table_entry_t* entry = hpack_header_table_get(context, result->value);
        fprintf(stderr, "Got header from table: %s, index: %ld\n", entry->name, result->value);
        key_name = entry->name;
        key_name_length = entry->name_length;
      }
      free(result);
      bool first_bit = get_bit(buf + current, 0);
      result = hpack_decode_quantity(buf + current, length - current, 1);
      current += result->num_bytes;
      size_t value_length = result->value;
      free(result);
      char* value = NULL;
      if (first_bit) {
        value = huffman_decode(buf + current, value_length);
      } else {
        value = malloc(value_length + 1);
        strncpy(value, buf + current, value_length);
        value[value_length] = '\0';
      }
      fprintf(stderr, "Adding literal: %s, %s\n", key_name, value);
      hpack_header_table_entry_t* header = hpack_header_table_add(context,
          key_name, key_name_length, value, value_length);
      headers = hpack_emit_header(headers, header->name, header->name_length,
          header->value, header->value_length);
      current += value_length;
    } else if (first_bit) {
      // indexed header field (4.2)
      hpack_decode_quantity_result_t* result = hpack_decode_quantity(buf + current, length - current, 1);
      current += result->num_bytes;
      fprintf(stderr, "Adding indexed header field: %ld\n", result->value);
      if (result->value == 0) {
        fprintf(stderr, "Empty reference set\n");
        hpack_reference_set_clear(context);
      } else {
        // if the value is in the reference set - remove it from the reference set
        if (hpack_reference_set_contains(context, result->value)) {
          hpack_reference_set_remove(context, result->value);
        } else {
          hpack_header_table_entry_t* entry = hpack_header_table_get(context,
              result->value);
          if (entry->from_static_table) {
            hpack_header_table_add_existing_entry(context, entry);
          }
          headers = hpack_emit_header(headers, entry->name,
              entry->name_length, entry->value, entry->value_length);
          fprintf(stderr, "From index: %s: %s\n", entry->name, entry->value);
        }
      }
    }
  }
  return headers;
}

hpack_encode_result_t* hpack_encode(hpack_context_t* context, hpack_headers_t* headers) {
  //naive hpack encoding - never add to the header table
  char* encoded = malloc(4096); // TODO - we need to construct this dynamically
  size_t encoded_index = 0;
  hpack_headers_t* header = headers;
  while (header) {
    fprintf(stderr, "Encoding Reponse Header: %s (%ld): %s (%ld)\n", header->name, header->name_length, header->value, header->value_length);
    encoded[encoded_index++] = 0x40; // 4.3.1. Literal Header Field without Indexing

    hpack_encode_quantity(encoded, encoded_index * 8, header->name_length);
    encoded_index++; // TODO - name_length might take up more than 1 byte
    // TODO huffman encode!
    strncpy(encoded + encoded_index, header->name, header->name_length);
    encoded_index += header->name_length;

    hpack_encode_quantity(encoded, encoded_index * 8, header->value_length);
    encoded_index++; // TODO - value_length might take up more than 1 byte
    // TODO huffman encode!
    strncpy(encoded + encoded_index, header->value, header->value_length);
    encoded_index += header->value_length;
    header = header->next;
  }
  hpack_encode_result_t* result = malloc(sizeof(hpack_encode_result_t));
  result->buf = encoded;
  result->buf_length = encoded_index;
  fprintf(stderr, "Encoded headers into %ld bytes\n", encoded_index);
  return result;
}

