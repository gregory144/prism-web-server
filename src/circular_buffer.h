
#ifndef HTTP_CIRCULAR_BUFFER_H
#define HTTP_CIRCULAR_BUFFER_H

#include <stdlib.h>
#include <stdbool.h>

typedef struct {
  size_t length;
  size_t capacity;
  size_t shift;
  void** entries;
} circular_buffer_t;

circular_buffer_t* circular_buffer_init(size_t capacity);

bool circular_buffer_add(circular_buffer_t* buf, void* entry);

bool circular_buffer_evict(circular_buffer_t* buf);

void* circular_buffer_get(circular_buffer_t* buf, size_t index);

void circular_buffer_free(circular_buffer_t* buf, void (free_entry)(void*));

#endif
