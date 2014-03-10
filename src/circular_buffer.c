#include "circular_buffer.h"

circular_buffer_t* circular_buffer_init(size_t capacity) {
  circular_buffer_t* buf = malloc(sizeof(circular_buffer_t));
  buf->entries = malloc(sizeof(void*) * capacity);
  if (buf) {
    buf->capacity = capacity;
    buf->length = 0;
    buf->shift = 0;
  }
  return buf;
}

circular_buffer_t* circular_buffer_resize(circular_buffer_t* buf, size_t new_capacity) {
  buf->entries = realloc(buf->entries, sizeof(circular_buffer_t));
  buf->capacity = new_capacity;
  return buf;
}

size_t circular_buffer_target_index(circular_buffer_t* buf, size_t index) {
  size_t length = buf->length;
  size_t shift = buf->shift;
  size_t capacity = buf->capacity;
  return (length - index + shift) % capacity;
}

bool circular_buffer_add(circular_buffer_t* buf, void* entry) {
  if (buf->length + 1 > buf->capacity) {
    if (!circular_buffer_resize(buf, buf->capacity * 2)) {
      return false;
    }
  }
  buf->length++;
  size_t target_index = circular_buffer_target_index(buf, 1);
  buf->entries[target_index] = entry;
  return true;
}

bool circular_buffer_evict(circular_buffer_t* buf) {
  buf->length--;
  buf->shift = (buf->shift + 1) % buf->capacity;
  return true;
}

void* circular_buffer_get(circular_buffer_t* buf, size_t index) {
  size_t target_index = circular_buffer_target_index(buf, index);
  return buf->entries[target_index];
}

void circular_buffer_free(circular_buffer_t* buf, void (free_entry)(void*)) {
  while (buf->length > 0) {
    void* entry = circular_buffer_get(buf, buf->length);
    free_entry(entry);
    circular_buffer_evict(buf);
  }
  free(buf->entries);
  free(buf);
}
