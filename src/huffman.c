#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#include "huffman_data.c"

extern const size_t huffman_decoder_size;
extern const huffman_entry_t huffman_decoder_table[];

int get_bit(char* buffer, size_t total_bit_index) {
  char* at_byte = buffer + (total_bit_index / 8);
  size_t bit_index = total_bit_index % 8;

  int b = *at_byte;
  int shifted = b >> (7 - bit_index);
  int res = shifted & 1;
  return res;
}

char* huffman_decode(char* input, size_t input_length) {
  // Every 4 bits might represent a character, so a char can be 2 characters
  size_t output_length = (input_length * 2) + 1;
  char* output = calloc(sizeof(char), output_length);
  size_t output_index = 0,
         input_index = 0;

  //fprintf(stderr, "starting index: %ld\n", huffman_decoder_size);
  huffman_entry_t current = huffman_decoder_table[huffman_decoder_size - 1];
  bool bit = get_bit(input, input_index++);
  while (input_index <= input_length * 8) {
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
  output[output_index] = '\0';
  return output;
}

char* huffman_encode(char* buf, size_t len) {
}

