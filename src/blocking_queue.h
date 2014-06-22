#ifndef HTTP_BLOCKING_QUEUE_H
#define HTTP_BLOCKING_QUEUE_H

#include <uv.h>

typedef struct blocking_queue_node_s {

  struct blocking_queue_node_s * next;

  void * data;

} blocking_queue_node_t;

typedef struct {

  blocking_queue_node_t * head;

  blocking_queue_node_t * tail;

  uv_mutex_t mutex;
  uv_cond_t nonempty;

  size_t length;
  size_t num_pushes;
  size_t num_pops;

} blocking_queue_t;

blocking_queue_t * blocking_queue_init();

void blocking_queue_push(blocking_queue_t * q, void * data);

void * blocking_queue_timed_pop(blocking_queue_t * q, uint64_t timeout_in_ns);
void * blocking_queue_try_pop(blocking_queue_t * q);

void blocking_queue_free(blocking_queue_t * q);

#endif

