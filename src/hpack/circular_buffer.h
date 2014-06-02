
#ifndef HTTP_CIRCULAR_BUFFER_H
#define HTTP_CIRCULAR_BUFFER_H

#include <stdlib.h>
#include <stdbool.h>

typedef struct {
  size_t length;
  size_t capacity;
  size_t shift;
  void ** entries;
} circular_buffer_t;

typedef struct {
  const circular_buffer_t * buf;
  size_t index;
  void * value;
} circular_buffer_iter_t;

circular_buffer_t * circular_buffer_init(const size_t capacity);

bool circular_buffer_add(circular_buffer_t * const buf, void * entry);

void * circular_buffer_get(const circular_buffer_t * const buf, const size_t index);

void * circular_buffer_evict(circular_buffer_t * const buf);

void circular_buffer_iterator_init(circular_buffer_iter_t * const iter, const circular_buffer_t * const buf);

bool circular_buffer_iterate(circular_buffer_iter_t * const iter);

void circular_buffer_free(circular_buffer_t * const buf, void (free_entry)(void *));

#endif

