#include <stdlib.h>
#include <string.h>

#include "../util/util.h"
#include "header_list.h"

header_list_t * header_list_init(header_list_t * header_list)
{
  if (header_list == NULL) {
    header_list = malloc(sizeof(header_list_t));
  }

  ASSERT_OR_RETURN_NULL(header_list);

  header_list->head = NULL;
  header_list->tail = NULL;
  header_list->size = 0;

  return header_list;
}

size_t header_list_size(header_list_t * list)
{
  return list->size;
}

header_list_linked_field_t * header_list_get(header_list_t * list, const char * const name,
    header_list_linked_field_t * prev)
{
  header_list_linked_field_t * curr = list->head;

  if (prev) {
    curr = prev;
  }

  while (curr) {
    log_trace("Comparing name %s to %s (%ld)", curr->field.name, name, curr->field.name_length);

    if (strncasecmp(curr->field.name, name, curr->field.name_length) == 0) {
      log_trace("Found %s", curr->field.value);
      return curr;
    }

    curr = curr->next;
  }

  return NULL;
}

bool header_list_unshift(header_list_t * list, char * name, size_t name_length, bool free_name,
                         char * value, size_t value_length, bool free_value)
{
  header_list_linked_field_t * entry = malloc(sizeof(header_list_linked_field_t));
  ASSERT_OR_RETURN_NULL(entry);

  entry->field.name = name;
  entry->field.name_length = name_length;
  entry->free_name = free_name;
  entry->field.value = value;
  entry->field.value_length = value_length;
  entry->free_value = free_value;

  entry->next = list->head;
  list->head = entry;

  if (list->tail == NULL) {
    list->tail = list->head;
  }

  return true;
}

bool header_list_push(header_list_t * list, char * name, size_t name_length, bool free_name,
                      char * value, size_t value_length, bool free_value)
{
  header_list_linked_field_t * entry = malloc(sizeof(header_list_linked_field_t));
  ASSERT_OR_RETURN_NULL(entry);

  entry->next = NULL;
  entry->field.name = name;
  entry->field.name_length = name_length;
  entry->free_name = free_name;
  entry->field.value = value;
  entry->field.value_length = value_length;
  entry->free_value = free_value;

  if (list->head == NULL) {
    list->head = entry;
  } else if (list->head == list->tail) {
    list->head->next = entry;
  } else {
    list->tail->next = entry;
  }

  list->tail = entry;

  return true;
}

void header_list_remove_pseudo_headers(header_list_t * header_list)
{
  header_list_linked_field_t * curr = header_list->head;
  header_list_linked_field_t * next = NULL;

  while (curr) {
    next = curr->next;

    if (curr->field.name[0] != ':') {
      break;
    }

    if (curr->free_name) {
      free(curr->field.name);
    }

    if (curr->free_value) {
      free(curr->field.value);
    }

    free(curr);
    header_list->size--;

    curr = next;
  }

  header_list->head = curr;

  if (header_list->size == 1) {
    header_list->tail = curr;
  }
}

void header_list_iterator_init(header_list_iter_t * iter, header_list_t * list)
{
  iter->list = list;
  iter->curr = NULL;
  iter->field = NULL;
}

bool header_list_iterate(header_list_iter_t * iter)
{
  if (iter->curr == NULL) {
    iter->curr = iter->list->head;
  } else {
    iter->curr = iter->curr->next;
  }

  if (iter->curr == NULL) {
    iter->field = NULL;
  } else {
    iter->field = &iter->curr->field;
  }

  return iter->curr;
}

void header_list_free(header_list_t * list)
{
  header_list_linked_field_t * curr = list->head;
  header_list_linked_field_t * next = NULL;

  while (curr) {
    next = curr->next;

    if (curr->free_name) {
      free(curr->field.name);
    }

    if (curr->free_value) {
      free(curr->field.value);
    }

    free(curr);

    curr = next;
  }

  free(list);
}
