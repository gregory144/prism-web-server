
#ifndef HTTP_MULTIMAP_H
#define HTTP_MULTIMAP_H

#include <stdlib.h>
#include <stdbool.h>

typedef struct multimap_values_s {
  struct multimap_values_s * next;
  void * key;
  void * value;
} multimap_values_t;

/**
 * Map entry
 */
typedef struct multimap_entry_s {
  struct multimap_entry_s * next;
  size_t size;
  void * key;
  multimap_values_t * values;
  multimap_values_t first_value;
} multimap_entry_t;

typedef size_t (*hash_func_t)(void * key);

typedef int (*hash_cmp_key_func_t)(void * key1, void * key2);

typedef void (*free_func_t)(void * x);

typedef struct {
  multimap_entry_t ** buckets;
  size_t capacity;
  size_t size;
  hash_func_t hash_func;
  hash_cmp_key_func_t cmp_key_func;
} multimap_t;

typedef struct {
  multimap_t * table;
  size_t index;
  multimap_entry_t * entry;
  multimap_entry_t * next;
  multimap_values_t * values;
  void * key;
  void * value;
} multimap_iter_t;

multimap_t * multimap_init_with_string_keys();

multimap_t * multimap_init_with_string_keys_and_size(const size_t initial_size);

multimap_t * multimap_init_with_int_keys();

multimap_t * multimap_init_with_int_keys_and_size(const size_t initial_size);

multimap_t * multimap_init_with_size(const hash_func_t hash_func,
                                     const hash_cmp_key_func_t cmp_key_func, const size_t initial_size);

multimap_t * multimap_init(const hash_func_t hash_func,
                           const hash_cmp_key_func_t cmp_key_func);

multimap_values_t * multimap_get(const multimap_t * const table, void * key);

bool multimap_put(multimap_t * const table, void * key, void * value);

size_t multimap_size(multimap_t * const map);

void multimap_remove(multimap_t * const table, void * key, const free_func_t free_key, const free_func_t free_value);

void multimap_iterator_init(multimap_iter_t * const iter, multimap_t * table);

bool multimap_iterate(multimap_iter_t * const iter);

void multimap_free(multimap_t * const table, const free_func_t free_key, const free_func_t free_value);

#endif
