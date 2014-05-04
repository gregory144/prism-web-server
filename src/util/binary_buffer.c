#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "util.h"
#include "binary_buffer.h"

binary_buffer_t * binary_buffer_init(binary_buffer_t * buffer, size_t capacity) {
  if (!buffer) {
    buffer = malloc(sizeof(binary_buffer_t));
    ASSERT_OR_RETURN_NULL(buffer);
  }
  buffer->index = 0;
  buffer->capacity = capacity;
  if (capacity > 0) {
    buffer->buf = malloc(capacity * sizeof(uint8_t));
    ASSERT_OR_RETURN_NULL(buffer->buf);
  } else {
    buffer->buf = NULL;
  }
  return buffer;
}

uint8_t binary_buffer_read_index(const binary_buffer_t * const buffer, size_t index) {
  if (index < buffer->capacity) {
    return buffer->buf[index];
  }
  return 0;
}

size_t binary_buffer_size(const binary_buffer_t * const buffer) {
  return buffer->index;
}

static bool binary_buffer_grow(binary_buffer_t * const buffer, size_t value_length) {
  size_t new_size = roundup_to_power_of_2((buffer->capacity + value_length) * 2);
  uint8_t * new_buf = realloc(buffer->buf, new_size);
  ASSERT_OR_RETURN_FALSE(new_buf);
  buffer->buf = new_buf;
  buffer->capacity = new_size;
  return true;
}

bool binary_buffer_write(binary_buffer_t * const buffer, uint8_t * value, size_t value_length) {
  size_t index = buffer->index;
  if (index + value_length > buffer->capacity) {
    ASSERT_OR_RETURN_FALSE(binary_buffer_grow(buffer, value_length));
  }
  if (value_length == 1) {
    buffer->buf[index] = *value;
  } else {
    uint8_t * ret = memcpy(buffer->buf + index, value, value_length);
    ASSERT_OR_RETURN_FALSE(ret);
  }
  if (buffer->index < buffer->index + value_length) {
    buffer->index += value_length;
  }
  return true;
}

bool binary_buffer_write_curr_index(binary_buffer_t * const buffer, uint8_t value) {
  return binary_buffer_write(buffer, &value, 1);
}

void binary_buffer_free(binary_buffer_t * const buffer) {
  free(buffer->buf);
  free(buffer);
}

