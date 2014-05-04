
#ifndef HTTP_BINARY_BUFFER_H
#define HTTP_BINARY_BUFFER_H

#include <stdbool.h>

typedef struct {
  size_t capacity;
  size_t index;
  uint8_t * buf;
} binary_buffer_t;

binary_buffer_t * binary_buffer_init(binary_buffer_t * result, size_t capacity);

uint8_t binary_buffer_read_index(const binary_buffer_t * const buffer, size_t index);

size_t binary_buffer_size(const binary_buffer_t * const buffer);

bool binary_buffer_write(binary_buffer_t * const buffer, uint8_t * value, size_t value_length);

bool binary_buffer_write_curr_index(binary_buffer_t * const buffer, uint8_t value);

void binary_buffer_free(binary_buffer_t * const buffer);

#endif
