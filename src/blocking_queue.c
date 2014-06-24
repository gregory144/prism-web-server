#include <stdlib.h>
#include <stdio.h>

#include <uv.h>

#include "blocking_queue.h"

blocking_queue_t * blocking_queue_init()
{
  blocking_queue_t * q = malloc(sizeof(blocking_queue_t));
  uv_mutex_init(&q->mutex);
  uv_cond_init(&q->nonempty);

  q->length = 0;
  q->num_pushes = 0;
  q->num_pops = 0;
  q->head = NULL;
  q->tail = NULL;
  return q;
}

void blocking_queue_push(blocking_queue_t * q, void * data)
{
  blocking_queue_node_t * new_node = malloc(sizeof(blocking_queue_node_t));
  new_node->next = NULL;
  new_node->data = data;

  uv_mutex_lock(&q->mutex);

  if (!q->head || !q->tail) {
    q->head = new_node;
    q->tail = new_node;
  } else {
    q->tail->next = new_node;
    q->tail = new_node;
  }

  q->length++;
  q->num_pushes++;

  uv_cond_signal(&q->nonempty);
  uv_mutex_unlock(&q->mutex);

}

static blocking_queue_node_t * blocking_queue_pop_internal(blocking_queue_t * q)
{
  blocking_queue_node_t * head = q->head;
  blocking_queue_node_t * next = head->next;
  q->head = next;

  if (head == q->tail) {
    q->tail = NULL;
  }

  q->length--;
  q->num_pops++;

  return head;
}

void * blocking_queue_timed_pop(blocking_queue_t * q, uint64_t timeout_in_ns)
{
  uv_mutex_lock(&q->mutex);

  while (q->length == 0) {
    int ret = uv_cond_timedwait(&q->nonempty, &q->mutex, timeout_in_ns);

    if (ret == UV_ETIMEDOUT) {
      uv_mutex_unlock(&q->mutex);
      return NULL;
    }
  }

  blocking_queue_node_t * head = blocking_queue_pop_internal(q);

  uv_mutex_unlock(&q->mutex);

  void * data = head->data;
  free(head);

  return data;
}

void * blocking_queue_try_pop(blocking_queue_t * q)
{
  uv_mutex_lock(&q->mutex);

  void * data = NULL;

  if (q->length > 0) {

    blocking_queue_node_t * head = blocking_queue_pop_internal(q);

    data = head->data;
    free(head);

  }

  uv_mutex_unlock(&q->mutex);

  return data;
}

void blocking_queue_free(blocking_queue_t * q)
{
  // TODO Pop all items first

  uv_cond_destroy(&q->nonempty);
  uv_mutex_destroy(&q->mutex);
  free(q);
}

