#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#include "util.h"

#include "huffman_decoder_data.c"
#include "huffman_encoder_data.c"

bool huffman_decode(const uint8_t * const input, const size_t input_length_in_octets, huffman_result_t * const result)
{
  const size_t input_length = input_length_in_octets * 8;
  // Every 4 bits might represent a character, so a char can be 2 characters
  const size_t output_length = (input_length / 4) + 1;
  uint8_t * const output = malloc(sizeof(uint8_t) * output_length);
  ASSERT_OR_RETURN_FALSE(output);

  size_t output_index = 0,
         input_index = 0;

  huffman_decoder_entry_t current = huffman_decoder_table[huffman_decoder_size - 1];
  bool bit = get_bit(input, input_index++);

  while (input_index <= input_length) {
    if (current.value != -1) {
      output[output_index++] = current.value;
      current = huffman_decoder_table[huffman_decoder_size - 1];
    } else if (bit == 0 && current.left != -1) {
      current = huffman_decoder_table[current.left];
      bit = get_bit(input, input_index++);
    } else if (bit == 1 && current.right != -1) {
      current = huffman_decoder_table[current.right];
      bit = get_bit(input, input_index++);
    }
  }

  if (current.value != -1) {
    output[output_index++] = current.value;
  }

  result->value = output;
  result->length = output_index;
  return true;
}

bool huffman_encode(const char * const buf, const size_t len, huffman_result_t * const result)
{
  size_t max_len = len;
  uint8_t * encoded = malloc(sizeof(uint8_t) * (max_len + 1));
  ASSERT_OR_RETURN_FALSE(encoded);

  size_t encoded_index = 0;
  uint8_t bits_left_in_byte = 8;
  uint8_t current_byte = 0;

  size_t buf_index;

  for (buf_index = 0; buf_index < len; buf_index++) {

    size_t to_encode = (size_t) buf[buf_index];
    huffman_encoder_entry_t entry = huffman_encoder_table[to_encode];

    uint32_t entry_value = entry.value;
    uint8_t pos_in_entry = entry.length;
    bool bit;

    while (pos_in_entry > 0) {
      bit = entry_value & (1 << (pos_in_entry - 1));
      current_byte |= bit;
      bits_left_in_byte--;
      pos_in_entry--;

      if (bits_left_in_byte == 0) {

        // make sure there is enough room to write the extra byte
        if (encoded_index >= max_len) {
          max_len += max_len;
          encoded = realloc(encoded, sizeof(uint8_t) * (max_len + 1));
          ASSERT_OR_RETURN_FALSE(encoded);
        }

        encoded[encoded_index++] = current_byte;

        current_byte = 0;
        bits_left_in_byte = 8;
      } else {
        current_byte = current_byte << 1;
      }
    }
  }

  if (bits_left_in_byte != 8) {
    current_byte = current_byte << (bits_left_in_byte - 1);
    // pad with 1's
    current_byte |= (1 << bits_left_in_byte) - 1;
    encoded[encoded_index++] = current_byte;
  }

  encoded[encoded_index] = 0x0;

  result->value = encoded;
  result->length = encoded_index;
  return true;
}

