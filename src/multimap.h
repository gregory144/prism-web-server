
#ifndef HTTP_multimap_H
#define HTTP_multimap_H

#include <stdlib.h>
#include <stdbool.h>

/**
 * Hash table entry
 */
typedef struct multimap_entry_s multimap_entry_t;
struct multimap_entry_s {
  multimap_entry_t* next;
  void* key;
  void* value;
};

typedef size_t (*hash_func_t)(void* key);

typedef int (*hash_cmp_key_func_t)(void* key1, void* key2);

typedef void (*free_func_t)(void* x);

typedef struct multimap_s multimap_t;
struct multimap_s {
  multimap_entry_t** entries;
  size_t capacity;
  size_t size;
  hash_func_t hash_func;
  hash_cmp_key_func_t cmp_key_func;
};

typedef struct {
  multimap_t* table;
  size_t index;
  multimap_entry_t* entry;
  multimap_entry_t* next;
  void* key;
  void* value;
} multimap_iter_t;

multimap_t* multimap_init_with_string_keys();

multimap_t* multimap_init_with_string_keys_and_size(
  size_t initial_size);

multimap_t* multimap_init_with_size(hash_func_t hash_func,
    hash_cmp_key_func_t cmp_key_func, size_t initial_size);

multimap_t* multimap_init(hash_func_t hash_func,
    hash_cmp_key_func_t cmp_key_func);

void* multimap_get(multimap_t* table, void* key);

void* multimap_put(multimap_t* table, void* key, void* value);

void* multimap_remove(multimap_t* table, void* key);

void multimap_iterator_init(multimap_iter_t* iter, multimap_t* table);

bool multimap_iterate(multimap_iter_t* iter);

void multimap_free(multimap_t* table, free_func_t free_key, free_func_t free_value);

#endif
