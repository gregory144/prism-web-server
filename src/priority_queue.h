
#ifndef HTTP_PRIORITY_QUEUE_H
#define HTTP_PRIORITY_QUEUE_H

#include <stdlib.h>
#include <stdbool.h>

typedef struct priority_queue_entry_s {

  size_t priority;

  bool valid;

  void * value;

} priority_queue_entry_t;

typedef struct priority_queue_ref_s {

  priority_queue_entry_t * entry;

} priority_queue_ref_t;

typedef struct {

  priority_queue_ref_t * refs;

  size_t capacity;

  size_t size;

} priority_queue_t;

priority_queue_t * priority_queue_init(size_t capacity);

size_t priority_queue_size(priority_queue_t * pq);

void * priority_queue_pop(priority_queue_t * pq);

priority_queue_entry_t * priority_queue_push(priority_queue_t * pq, size_t priority, void * value);

void priority_queue_modify_priority(priority_queue_t * pq, priority_queue_entry_t * entry, size_t priority);

void priority_queue_free(priority_queue_t * pq);

#endif
