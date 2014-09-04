#include <stdint.h>

#include "priority_queue.h"

priority_queue_t * priority_queue_init(size_t capacity)
{
  priority_queue_t * pq = malloc(sizeof(priority_queue_t));
  pq->refs = malloc(sizeof(priority_queue_ref_t) * capacity);
  pq->capacity = capacity;
  pq->size = 0;
  return pq;
}

size_t priority_queue_size(priority_queue_t * pq)
{
  return pq->size;
}

size_t left_child_index(size_t root)
{
  return 2 * root + 1;
}

size_t right_child_index(size_t root)
{
  return 2 * root + 2;
}

size_t parent_index(size_t child)
{
  return (child - 1) / 2; // rely on integer truncation
}

void swap_entries(priority_queue_ref_t * root, priority_queue_ref_t * child)
{
  priority_queue_entry_t * temp = root->entry;
  root->entry = child->entry;
  child->entry = temp;
}

void bubble_down(priority_queue_t * pq)
{
  priority_queue_ref_t last_ref = pq->refs[pq->size];
  pq->refs[0].entry = last_ref.entry;

  size_t index = 0;

  while (1) {
    priority_queue_ref_t * current = &pq->refs[index];
    priority_queue_ref_t * left = NULL;
    priority_queue_ref_t * right = NULL;
    size_t left_index = left_child_index(index);

    if (left_index < pq->size) {
      left = &pq->refs[left_index];
    }

    size_t right_index = right_child_index(index);

    if (right_index < pq->size) {
      right = &pq->refs[right_index];
    }

    size_t current_priority = current->entry->priority;
    size_t left_priority = left ? left->entry->priority : SIZE_MAX;
    size_t right_priority = right ? right->entry->priority : SIZE_MAX;

    if (left_priority < current_priority && left_priority < right_priority) {
      swap_entries(current, left);
      index = left_index;
    } else if (right_priority < current_priority && right_priority < left_priority) {
      swap_entries(current, right);
      index = right_index;
    } else {
      break;
    }
  }
}

void bubble_up(priority_queue_t * pq)
{
  size_t index = pq->size - 1;

  while (1) {
    if (index == 0) {
      break;
    }

    priority_queue_ref_t * current = &pq->refs[index];
    size_t parent_idx = parent_index(index);
    priority_queue_ref_t * parent = &pq->refs[parent_idx];

    size_t current_priority = current->entry->priority;
    size_t parent_priority = parent->entry->priority;

    if (parent_priority > current_priority) {
      swap_entries(current, parent);
      index = parent_idx;
    } else {
      break;
    }
  }
}

void * priority_queue_pop(priority_queue_t * pq)
{
  priority_queue_entry_t * entry = NULL;

  if (pq->size > 0) {
    do {
      priority_queue_ref_t ref = pq->refs[0];
      entry = ref.entry;
      pq->size--;

      if (pq->size > 0) {
        bubble_down(pq);
      }
    } while (pq->size > 0 && !entry->valid);
  }

  return entry ? entry->value : NULL;
}

priority_queue_entry_t * priority_queue_push(priority_queue_t * pq, size_t priority, void * value)
{
  if (pq->size >= pq->capacity) {
    // TODO GROW!
    abort();
  }

  priority_queue_entry_t * new_entry = malloc(sizeof(priority_queue_entry_t));
  new_entry->priority = priority;
  new_entry->value = value;
  new_entry->valid = true;

  pq->refs[pq->size].entry = new_entry;
  pq->size++;

  bubble_up(pq);

  return new_entry;
}

void priority_queue_modify_priority(priority_queue_t * pq, priority_queue_entry_t * entry, size_t priority)
{
  entry->valid = false;
  priority_queue_push(pq, priority, entry->value);
}

void priority_queue_free(priority_queue_t * pq)
{
  size_t i;

  for (i = 0; i < pq->size; i++) {
    free(pq->refs[i].entry);
  }

  free(pq->refs);
  free(pq);
}

