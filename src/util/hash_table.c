#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "hash_table.h"
#include "util.h"

#define DEFAULT_HASH_TABLE_INITIAL_CAPACITY 128

/**
 * From http://www.cse.yorku.ca/~oz/hash.html
 */
static size_t string_hash(const void * const key)
{
  const unsigned char * string_key = key;
  size_t hash = 5381;
  int c;

  while ((c = *string_key++)) {
    hash = ((hash << 5) + hash) + c;  /* hash * 33 + c */
  }

  return hash;
}

static size_t int_hash(const void * const key)
{
  size_t i = * (long *) key;
  return i * 2654435761;
}

static int string_cmp_key(const void * const key1, const void * const key2)
{
  return strcmp(key1, key2);
}

static int int_cmp_key(const void * const key1, const void * const key2)
{
  const long k1 = * (const long * const) key1;
  const long k2 = * (const long * const) key2;
  return k1 - k2;
}

hash_table_t * hash_table_init_with_string_keys(
  hash_table_t * ht,
  hash_table_free_func_t free_value
)
{

  return hash_table_init_with_string_keys_and_capacity(
           ht, DEFAULT_HASH_TABLE_INITIAL_CAPACITY, free_value);

}

hash_table_t * hash_table_init_with_string_keys_and_capacity(
  hash_table_t * ht,
  size_t initial_capacity,
  hash_table_free_func_t free_value
)
{

  return hash_table_init_with_capacity(ht, string_hash, string_cmp_key,
                                       initial_capacity, free, free_value);

}

hash_table_t * hash_table_init_with_int_keys(
  hash_table_t * ht,
  hash_table_free_func_t free_value
)
{

  return hash_table_init_with_int_keys_and_capacity(
           ht, DEFAULT_HASH_TABLE_INITIAL_CAPACITY, free_value);

}

hash_table_t * hash_table_init_with_int_keys_and_capacity(
  hash_table_t * ht,
  size_t initial_capacity,
  hash_table_free_func_t free_value
)
{

  return hash_table_init_with_capacity(ht, int_hash, int_cmp_key,
                                       initial_capacity, free, free_value);

}

hash_table_t * hash_table_init(
  hash_table_t * ht,
  hash_table_hash_func_t hash_func,
  hash_table_cmp_key_func_t cmp_key_func,
  hash_table_free_func_t free_key,
  hash_table_free_func_t free_value
)
{

  return hash_table_init_with_capacity(ht, hash_func, cmp_key_func,
                                       DEFAULT_HASH_TABLE_INITIAL_CAPACITY, free_key, free_value);

}

hash_table_t * hash_table_init_with_capacity(
  hash_table_t * ht,
  hash_table_hash_func_t hash_func,
  hash_table_cmp_key_func_t cmp_key_func,
  size_t initial_capacity,
  hash_table_free_func_t free_key,
  hash_table_free_func_t free_value
)
{
  bool free_on_err = false;
  if (!ht) {
    free_on_err = true;
    ht = malloc(sizeof(hash_table_t));
  }
  ASSERT_OR_RETURN_NULL(ht);

  ht->buckets = calloc(initial_capacity, sizeof(hash_table_entry_t *));

  if (!ht->buckets) {
    if (free_on_err) {
      free(ht);
    }
    return NULL;
  }

  ht->hash_func = hash_func;
  ht->cmp_key_func = cmp_key_func;
  ht->size = 0;
  ht->capacity = initial_capacity;
  ht->free_key = free_key;
  ht->free_value = free_value;
  return ht;
}

static size_t hash_key(const hash_table_t * const table, size_t capacity, const void * const key)
{
  size_t hash_value = table->hash_func(key);
  return hash_value % capacity;
}

size_t hash_table_size(hash_table_t * table)
{
  return table->size;
}

static hash_table_entry_t * hash_table_get_entry(hash_table_t * table, const void * const key)
{
  size_t hash_value = hash_key(table, table->capacity, key);
  hash_table_entry_t * current;

  for (current = table->buckets[hash_value]; current != NULL;
       current = current->next) {
    if (table->cmp_key_func(key, current->key) == 0) {
      // found
      return current;
    }
  }

  // not found
  return NULL;
}

void * hash_table_get(hash_table_t * table, const void * const key)
{
  hash_table_entry_t * entry = hash_table_get_entry(table, key);

  if (entry) {
    return entry->value;
  }

  // not found
  return NULL;
}

static bool hash_table_grow(hash_table_t * table)
{
  size_t new_capacity = table->capacity * 2;
  hash_table_entry_t ** new_buckets = calloc(new_capacity, sizeof(hash_table_entry_t *));
  ASSERT_OR_RETURN_FALSE(new_buckets);
  // iterate through all buckets in table and re-insert into
  // new table
  size_t i;

  for (i = 0; i < table->capacity; i++) {
    hash_table_entry_t * current = table->buckets[i];

    while (current) {
      hash_table_entry_t * next = current->next;

      // find which bucket to place the entry in in the new array of buckets
      size_t hash_value = hash_key(table, new_capacity, current->key);
      current->next = new_buckets[hash_value];
      new_buckets[hash_value] = current;

      current = next;
    }
  }

  free(table->buckets);
  table->buckets = new_buckets;
  table->capacity = new_capacity;

  return true;
}

bool hash_table_put(hash_table_t * table, void * key, void * value)
{

  hash_table_entry_t * entry;

  if ((entry = hash_table_get_entry(table, key)) == NULL) {
    // not found

    // grow the table if necessary
    if ((table->size + 1.0) / table->capacity > 0.75) {
      if (!hash_table_grow(table)) {
        return false;
      }
    }

    // create a new entry and put it in the table
    entry = malloc(sizeof(hash_table_entry_t));
    ASSERT_OR_RETURN_FALSE(entry);
    entry->key = key;

    size_t hash_value = hash_key(table, table->capacity, key);
    entry->next = table->buckets[hash_value];
    table->buckets[hash_value] = entry;
    table->size++;

  } else {
    // the key already exists in the table

    // free previous key
    table->free_key(entry->key);
    // free previous value
    table->free_value(entry->value);

    entry->key = key;
  }

  entry->value = value;

  return true;
}

bool hash_table_remove(hash_table_t * table, void * key)
{
  size_t hash_value = hash_key(table, table->capacity, key);
  hash_table_entry_t * current;
  hash_table_entry_t * prev = NULL;

  for (current = table->buckets[hash_value]; current != NULL;
       current = current->next) {
    if (table->cmp_key_func(key, current->key) == 0) {
      if (prev) {
        prev->next = current->next;
      } else {
        table->buckets[hash_value] = current->next;
      }

      void * value = current->value;
      table->free_key(current->key);
      table->free_value(current->value);
      free(current);
      table->size--;

      return true;
    }
    prev = current;
  }

  return false;
}

void hash_table_iterator_init(hash_table_iter_t * iter, hash_table_t * table)
{
  iter->entry = NULL;
  iter->index = 0;
  iter->table = table;
}

bool hash_table_iterate(hash_table_iter_t * iter)
{
  hash_table_t * table = iter->table;
  hash_table_entry_t * entry = iter->entry;

  if (entry && entry->next) {
    entry = entry->next;
  } else if (iter->index < table->capacity) {
    do {
      entry = table->buckets[iter->index];
      iter->index++;
    } while (!entry && iter->index < table->capacity);
  } else {
    entry = NULL;
  }

  if (entry) {
    iter->key = entry->key;
    iter->value = entry->value;
  }

  iter->entry = entry;
  return iter->entry != NULL;
}

void hash_table_free(hash_table_t * table)
{
  size_t i;

  for (i = 0; i < table->capacity; i++) {
    hash_table_entry_t * entry = table->buckets[i];
    hash_table_entry_t * current;

    while (entry) {
      current = entry;
      entry = entry->next;
      table->free_key(current->key);
      table->free_value(current->value);
      free(current);
    }
  }

  free(table->buckets);
}
