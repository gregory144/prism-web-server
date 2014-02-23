#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#include "util.h"

#include "huffman_data.c"

extern const size_t huffman_decoder_size;
extern const huffman_entry_t huffman_decoder_table[];

char* huffman_decode(char* input, size_t input_length_in_octets) {
  size_t input_length = input_length_in_octets * 8;
  fprintf(stderr, "Input length: %ld\n", input_length);
  // Every 4 bits might represent a character, so a char can be 2 characters
  size_t output_length = (input_length / 4) + 1;
  char* output = calloc(sizeof(char), output_length);
  size_t output_index = 0,
         input_index = 0;

  //fprintf(stderr, "starting index: %ld\n", huffman_decoder_size);
  huffman_entry_t current = huffman_decoder_table[huffman_decoder_size - 1];
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
}

