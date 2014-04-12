#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "huffman.h"

int main(int argc, char* argv[]) {

  bool print_stats = false;

  bool decode = false;
  bool encode = true;

  if (argc > 1) {
    size_t arg_index;
    for (arg_index = 1; arg_index < (size_t)argc; arg_index++) {
      char* arg = argv[arg_index];
      if (strcmp(arg, "-s") == 0) {
        print_stats = true;
      } else if (strcmp(arg, "-d") == 0) {
        decode = true;
        encode = false;
      } else if (strcmp(arg, "-e") == 0) {
        decode = true;
        encode = true;
      } else {
        fprintf(stderr, "Unknown argument: %s\n", argv[arg_index]);
        exit(EXIT_FAILURE);
      }
    }
  }

  size_t block_size = 4096;
  uint8_t buffer[block_size];

  size_t bytes_read;
  size_t total_bytes_read = 0;
  size_t total_bytes_written = 0;
  do {
    bytes_read = fread(buffer, sizeof(uint8_t), block_size, stdin);
    total_bytes_read += bytes_read;

    uint8_t* intermediate = buffer;
    size_t intermediate_length = bytes_read;

    huffman_result_t* result;

    if (encode) {

      result = huffman_encode(intermediate, intermediate_length);
      if (!result) {
        fprintf(stderr, "Encode failed\n");
        exit(EXIT_FAILURE);
      }

      intermediate = result->value;
      intermediate_length = result->length;

    }

    if (decode) {

      result = huffman_decode(intermediate, intermediate_length);
      if (!result) {
        fprintf(stderr, "Decode failed\n");
        exit(EXIT_FAILURE);
      }

      intermediate = result->value;
      intermediate_length = result->length;

    }

    total_bytes_written += intermediate_length;

    if (!print_stats) {
      size_t bytes_written = fwrite(intermediate, sizeof(uint8_t), intermediate_length, stdout);
      if (bytes_written != intermediate_length) {
        fprintf(stderr, "Could not write result to stdout\n");
        exit(EXIT_FAILURE);
      }
    }

  } while (bytes_read > 0);

  if (print_stats) {
    double ratio = (total_bytes_written * 1.0) / total_bytes_read;
    fprintf(stdout, "Read: %ld bytes\nWrote: %ld bytes\nRatio: %.3f%%\n", total_bytes_read, total_bytes_written, ratio);
  }

  exit(EXIT_SUCCESS);
}

