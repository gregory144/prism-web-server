#ifndef HTTP_HEADER_LIST_H
#define HTTP_HEADER_LIST_H

#include <stdlib.h>

typedef struct {
  char * name;
  size_t name_length;
  char * value;
  size_t value_length;
} header_field_t;

typedef struct header_list_linked_field_s header_list_linked_field_t;
struct header_list_linked_field_s {
  header_list_linked_field_t * next;
  header_field_t field;
  bool free_name;
  bool free_value;
};

typedef struct {
  header_list_linked_field_t * head;
  header_list_linked_field_t * tail;
  size_t size;
} header_list_t;

typedef struct {
  header_list_t * list;
  header_list_linked_field_t * curr;
  header_field_t * field;
} header_list_iter_t;

header_list_t * header_list_init(header_list_t * header_list);

size_t header_list_size(header_list_t * list);

header_list_linked_field_t * header_list_get(header_list_t * list, const char * const name,
    header_list_linked_field_t * prev);

/**
 * Add a header at the beginning of the header list
 * (useful for adding pseudo headers)
 */
bool header_list_unshift(header_list_t * list, char * name, size_t name_length, bool free_name,
                         char * value, size_t value_length, bool free_value);

/**
 * Add a header at the end of the list
 */
bool header_list_push(header_list_t * list, char * name, size_t name_length, bool free_name,
                      char * value, size_t value_length, bool free_value);

void header_list_remove_pseudo_headers(header_list_t * header_list);

void header_list_iterator_init(header_list_iter_t * iter, header_list_t * list);

bool header_list_iterate(header_list_iter_t * iter);

void header_list_free(header_list_t * list);

#endif
