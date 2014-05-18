
#ifndef HTTP_HASH_TABLE_H
#define HTTP_HASH_TABLE_H

#include <stdlib.h>
#include <stdbool.h>

/**
 * Hash table entry
 */
typedef struct hash_table_entry_s hash_table_entry_t;
struct hash_table_entry_s {
  hash_table_entry_t * next;
  void * key;
  void * value;
};

typedef size_t (*hash_func_t)(void * key);

typedef int (*hash_cmp_key_func_t)(void * key1, void * key2);

typedef void (*free_func_t)(void * x);

typedef struct hash_table_s hash_table_t;
struct hash_table_s {
  hash_table_entry_t * * buckets;
  size_t capacity;
  size_t size;
  hash_func_t hash_func;
  hash_cmp_key_func_t cmp_key_func;
  free_func_t free_key;
  free_func_t free_value;
};

typedef struct {
  hash_table_t * table;
  size_t index;
  hash_table_entry_t * entry;
  hash_table_entry_t * next;
  void * key;
  void * value;
} hash_table_iter_t;

hash_table_t * hash_table_init_with_string_keys();

hash_table_t * hash_table_init_with_string_keys_and_size(
  size_t initial_size);

hash_table_t * hash_table_init_with_int_keys();

hash_table_t * hash_table_init_with_int_keys_and_size(
  size_t initial_size);

hash_table_t * hash_table_init_with_size(hash_func_t hash_func,
    hash_cmp_key_func_t cmp_key_func, size_t initial_size,
    free_func_t free_key, free_func_t free_value);

hash_table_t * hash_table_init(hash_func_t hash_func,
    hash_cmp_key_func_t cmp_key_func, free_func_t free_key, free_func_t free_value);

size_t hash_table_size(hash_table_t * table);

void * hash_table_get(hash_table_t * table, void * key);

bool hash_table_put(hash_table_t * table, void * key, void * value);

void * hash_table_remove(hash_table_t * table, void * key);

void hash_table_iterator_init(hash_table_iter_t * iter, hash_table_t * table);

bool hash_table_iterate(hash_table_iter_t * iter);

void hash_table_free(hash_table_t * table);

#endif
