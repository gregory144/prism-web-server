#include <stdio.h>
#include <string.h>

#include "circular_buffer.h"

circular_buffer_t * circular_buffer_init(const size_t capacity)
{
  circular_buffer_t * buf = malloc(sizeof(circular_buffer_t));
  if (!buf) {
    return NULL;
  }
  buf->entries = malloc(sizeof(void *) * capacity);
  if (!buf->entries) {
    free(buf);
    return NULL;
  }

  if (buf) {
    buf->capacity = capacity;
    buf->length = 0;
    buf->shift = 0;
  }

  return buf;
}

static circular_buffer_t * circular_buffer_grow(circular_buffer_t * const buf)
{
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
    void ** new_entries = malloc(sizeof(void *) * buf->capacity * 2);
    if (!new_entries) {
      return NULL;
    }

    size_t seg_a_length = shift + length - capacity;
    size_t seg_b_length = length - seg_a_length;
    memcpy(new_entries, buf->entries + shift, seg_b_length);
    memcpy(new_entries + seg_b_length, buf->entries, seg_a_length);
    free(buf->entries);
    buf->entries = new_entries;
    buf->shift = 0;
  } else {
    buf->entries = realloc(buf->entries, sizeof(void *) * buf->capacity * 2);
    if (!buf->entries) {
      return NULL;
    }
  }

  buf->capacity *= 2;
  return buf;
}

static size_t circular_buffer_target_index(const circular_buffer_t * const buf, const size_t index)
{
  size_t length = buf->length;
  size_t shift = buf->shift;
  size_t capacity = buf->capacity;
  return (length - index + shift) % capacity;
}

bool circular_buffer_add(circular_buffer_t * const buf, void * entry)
{
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

void * circular_buffer_get(const circular_buffer_t * const buf, const size_t index)
{
  size_t target_index = circular_buffer_target_index(buf, index);
  return buf->entries[target_index];
}

void * circular_buffer_evict(circular_buffer_t * const buf)
{
  void * last = circular_buffer_get(buf, buf->length);
  buf->length--;
  buf->shift = (buf->shift + 1) % buf->capacity;
  return last;
}

void circular_buffer_iterator_init(circular_buffer_iter_t * const iter, const circular_buffer_t * const buf)
{
  iter->index = 1;
  iter->buf = buf;
}

bool circular_buffer_iterate(circular_buffer_iter_t * const iter)
{
  const circular_buffer_t * const buf = iter->buf;
  size_t length = buf->length;
  size_t shift = buf->shift;
  size_t index = iter->index++;

  if (index <= length) {
    void ** entry = buf->entries + ((shift + index - 1) % buf->capacity);
    iter->value = *entry;
    return true;
  }

  return false;
}

void circular_buffer_free(circular_buffer_t * const buf, void (free_entry)(void *))
{
  circular_buffer_iter_t iter;
  circular_buffer_iterator_init(&iter, buf);

  while (circular_buffer_iterate(&iter)) {
    free_entry(iter.value);
  }

  free(buf->entries);
  free(buf);
}

