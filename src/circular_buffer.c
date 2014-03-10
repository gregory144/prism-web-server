#include <stdio.h>
#include <string.h>

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

circular_buffer_t* circular_buffer_grow(circular_buffer_t* buf) {
  // If the buffer wraps around the end of the array, we need to move the data around
  // so that we can still compute the indices correctly.
  // Say the buffer wraps around and splits the data into 2 segments:
  // segment a and segment b:
  // seg_a   seg_b
  // ---     ******
  // We need to reconfigure the data so that it looks like:
  // seg_b+seg_a
  // ******---
  size_t shift = buf->shift;
  size_t length = buf->length;
  size_t capacity = buf->capacity;
  if (shift + length > capacity) {
    void** new_entries = malloc(sizeof(void*) * buf->capacity * 2);

    size_t seg_a_length = shift + length - capacity;
    size_t seg_b_length = length - seg_a_length;
    memcpy(new_entries, buf->entries + shift, seg_b_length);
    memcpy(new_entries + seg_b_length, buf->entries, seg_a_length);
    free(buf->entries);
    buf->entries = new_entries;
    buf->shift = 0;
  } else {
    buf->entries = realloc(buf->entries, sizeof(void*) * buf->capacity * 2);
  }
  buf->capacity *= 2;
  return buf;
}

size_t circular_buffer_target_index(circular_buffer_t* buf, size_t index) {
  size_t length = buf->length;
  size_t shift = buf->shift;
  size_t capacity = buf->capacity;
  return (length - index + shift) % capacity;
}

bool circular_buffer_add(circular_buffer_t* buf, void* entry) {
  if (buf->length >= buf->capacity) {
    if (!circular_buffer_grow(buf)) {
      return false;
    }
  }
  buf->length++;
  size_t target_index = circular_buffer_target_index(buf, 1);
  buf->entries[target_index] = entry;
  return true;
}

void* circular_buffer_get(circular_buffer_t* buf, size_t index) {
  size_t target_index = circular_buffer_target_index(buf, index);
  return buf->entries[target_index];
}

void* circular_buffer_evict(circular_buffer_t* buf) {
  void* last = circular_buffer_get(buf, buf->length);
  buf->length--;
  buf->shift = (buf->shift + 1) % buf->capacity;
  return last;
}

void circular_buffer_free(circular_buffer_t* buf, void (free_entry)(void*)) {
  size_t length = buf->length;
  size_t shift = buf->shift;
  size_t i;
  for (i = 0; i < length; i++) {
    void** entry = buf->entries + ( (shift + i) % buf->capacity );
    free_entry(*entry);
  }
  free(buf->entries);
  free(buf);
}
