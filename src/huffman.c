#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#include "util.h"

#include "huffman_decoder_data.c"
#include "huffman_encoder_data.c"

extern const size_t huffman_decoder_size;
extern const huffman_decoder_entry_t huffman_decoder_table[];

char* huffman_decode(char* input, size_t input_length_in_octets) {
  size_t input_length = input_length_in_octets * 8;
  fprintf(stderr, "Input length: %ld\n", input_length);
  // Every 4 bits might represent a character, so a char can be 2 characters
  size_t output_length = (input_length / 4) + 1;
  char* output = calloc(sizeof(char), output_length);
  size_t output_index = 0,
         input_index = 0;

  //fprintf(stderr, "starting index: %ld\n", huffman_decoder_size);
  huffman_decoder_entry_t current = huffman_decoder_table[huffman_decoder_size - 1];
  bool bit = get_bit(input, input_index++);
  while (input_index <= input_length) {
    //fprintf(stderr, "bit: %d, input index: %ld\n", bit, input_index);
    //fprintf(stderr, "current: %d: value: %d\n", current.index, current.value);
    if (current.value != -1) {
      //fprintf(stderr, "value: %c\n", current.value);
      output[output_index++] = current.value;
      current = huffman_decoder_table[huffman_decoder_size - 1];
      //fprintf(stderr, "starting index: %ld\n", huffman_decoder_size);
    } else if (bit == 0 && current.left != -1) {
      //fprintf(stderr, "left index: %d\n", current.left);
      current = huffman_decoder_table[current.left];
      bit = get_bit(input, input_index++);
    } else if (bit == 1 && current.right != -1) {
      //fprintf(stderr, "right index: %d\n", current.right);
      current = huffman_decoder_table[current.right];
      bit = get_bit(input, input_index++);
    }
  }
  //fprintf(stderr, "finish: current: %d: value: %d\n", current.index, current.value);
  if (current.value != -1) {
    output[output_index++] = current.value;
  }
  fprintf(stderr, "Output and index: %s, %ld\n", output, output_index);
  output[output_index] = '\0';
  return output;
}

char* huffman_encode(char* buf, size_t len) {
  char* encoded = malloc(len + 1);
  int encoded_index = 0;
  int buf_index;
  //int bit_index = 0;

  int bits_left_in_byte = 8;
  unsigned char current_byte = 0;

  for (buf_index = 0; buf_index < len; buf_index++) {
    huffman_encoder_entry_t entry = huffman_encoder_table[buf[buf_index]];
    //put_bits(encoded, bit_index, entry.value, entry.length);
    //bit_index += entry.length;

    uint32_t entry_value = entry.value;
    uint8_t pos_in_entry = entry.length;
    fprintf(stderr, "encoding %c (%x) (%d)\n", buf[buf_index], entry_value, entry.length);
    bool bit;

    while (pos_in_entry > 0) {
      bit = entry_value & (1 << (pos_in_entry - 1));
      fprintf(stderr, "Bit: %d (%x) %d\n", entry_value, entry_value, bit);
      current_byte |= bit;
      bits_left_in_byte--;
      pos_in_entry--;
      if (bits_left_in_byte == 0) {
        fprintf(stderr, "writing %x\n", current_byte);
        encoded[encoded_index++] = current_byte;
        current_byte = 0;
        bits_left_in_byte = 8;
      } else {
        current_byte = current_byte << 1;
      }
    }
    fprintf(stderr, "Encoded 1 char: %c, buf_index: %d, len: %ld\n", buf[buf_index], buf_index, len);
  }
  if (bits_left_in_byte != 8) {
    current_byte = current_byte << (bits_left_in_byte - 1);
    fprintf(stderr, "without padding %d (%x)\n", current_byte, current_byte);
    // pad with 1's
    current_byte |= (1 << bits_left_in_byte) - 1;
    fprintf(stderr, "with padding %d (%x)\n", current_byte, current_byte);
    encoded[encoded_index++] = current_byte;
  }
  //int padding_length = 8 - (bit_index % 8);
  //if (padding_length % 8 != 0) {
  //  fprintf(stderr, "Padding with EOS %d bits\n", padding_length);
  //  huffman_encoder_entry_t eos_entry = huffman_encoder_table[256];
  //  put_bits(encoded, bit_index, eos_entry.value, eos_entry.length, padding_length);
  //}
  encoded[encoded_index] = 0x0;
  return encoded;
}

