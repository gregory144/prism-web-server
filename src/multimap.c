#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "multimap.h"
#include "util.h"

#define DEFAULT_multimap_INITIAL_SIZE 128

/**
 * From http://www.cse.yorku.ca/~oz/hash.html
 */
size_t string_hash(void* key) {
  unsigned char* string_key = key;
  size_t hash = 5381;
  int c;

  while ((c = *string_key++))
    hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

  return hash;
}

int string_cmp_key(void* key1, void* key2) {
  return strcmp(key1, key2);
}

multimap_t* multimap_init_with_string_keys() {
  return multimap_init_with_string_keys_and_size(
      DEFAULT_multimap_INITIAL_SIZE);
}

multimap_t* multimap_init_with_string_keys_and_size(
  size_t initial_size) {
  return multimap_init_with_size(string_hash, string_cmp_key,
      initial_size);
}

multimap_t* multimap_init(hash_func_t hash_func,
    hash_cmp_key_func_t cmp_key_func) {
  return multimap_init_with_size(hash_func, cmp_key_func,
      DEFAULT_multimap_INITIAL_SIZE);
}

multimap_t* multimap_init_with_size(hash_func_t hash_func,
    hash_cmp_key_func_t cmp_key_func, size_t initial_size) {
  multimap_t* table = malloc(sizeof(multimap_t));
  if (table == NULL) {
    return NULL;
  }
  table->entries = calloc(initial_size, sizeof(multimap_entry_t));
  if (table->entries == NULL) {
    return NULL;
  }
  table->hash_func = hash_func;
  table->cmp_key_func = cmp_key_func;
  table->size = 0;
  table->capacity = initial_size;
  return table;
}

size_t hash_key(multimap_t* table, void* key) {
  size_t hash_value = table->hash_func(key);
  return hash_value % table->capacity;
}

void* multimap_get(multimap_t* table, void* key) {
  size_t hash_value = hash_key(table, key);
  multimap_entry_t* current;
  for (current = table->entries[hash_value]; current != NULL;
      current = current->next) {
    if (table->cmp_key_func(key, current->key) == 0) {
      // found
      return current->value;
    }
  }
  // not found
  return NULL;
}

multimap_t* multimap_grow(multimap_t* table) {
  // TODO
  size_t new_size = table->capacity * 2;
  multimap_entry_t* new_entries = calloc(new_size,
      sizeof(multimap_entry_t));
  if (new_entries == NULL) {
    return NULL;
  }
  // iterate through all entries in table and re-insert into
  // new table
  for (size_t i = 0; i < table->capacity; i++) {
    multimap_entry_t *current = table->entries[i];
    for (; current != NULL; current = current->next) {
      // TODO
    }
  }
  return table;
} 

void* multimap_put(multimap_t* table, void* key, void* value) {
  multimap_entry_t *entry;
  if ((entry = multimap_get(table, key)) == NULL) {
    // not found

    // grow the table if necessary
    if ((table->size + 1.0) / table->capacity > 0.75) {
      if (multimap_grow(table) == NULL) {
        return NULL;
      }
    }

    // create a new entry and put it in the table
    entry = malloc(sizeof(multimap_entry_t));
    if (entry == NULL) {
      return NULL;
    }
    entry->key = key;
    size_t hash_value = hash_key(table, key);
    entry->next = table->entries[hash_value];
    table->entries[hash_value] = entry;
    table->size++;
  } else {
    // the key already exists in the table
    // free previous value
    free(entry->value);
  }
  entry->value = value;
  return entry->value;
}

void* multimap_remove(multimap_t* table, void* key) {
  size_t hash_value = hash_key(table, key);
  multimap_entry_t* current;
  multimap_entry_t* prev = NULL;
  for (current = table->entries[hash_value]; current != NULL;
      current = current->next) {
    if (table->cmp_key_func(key, current->key) == 0) {
      if (prev) {
        prev->next = current->next;
      } else {
        table->entries[hash_value] = current->next;
      }
      void* value = current->value;
      free(current);
      table->size--;
      return value;
    }
  }
  return NULL;
}

void multimap_iterator_init(multimap_iter_t* iter, multimap_t* table) {
  iter->entry = NULL;
  iter->next = NULL;
  iter->index = 0;
  iter->table = table;
}

bool multimap_iterate(multimap_iter_t* iter) {
  multimap_t* table = iter->table;
  multimap_entry_t* entry = iter->entry;
  if (entry && entry->next) {
    entry = entry->next;
  } else {
    do {
      entry = table->entries[iter->index];
      iter->index++;
    } while (!entry && iter->index < table->capacity);
  }
  if (entry) {
    iter->key = entry->key;
    iter->value = entry->value;
  }
  iter->entry = entry;
  return iter->entry != NULL;
}

void multimap_free(multimap_t* table, free_func_t free_key, free_func_t free_value) {
  size_t i;
  for (i = 0; i < table->capacity; i++) {
    multimap_entry_t* entry = table->entries[i];
    multimap_entry_t* current;
    while (entry) {
      current = entry;
      entry = entry->next;
      free_key(current->key);
      free_value(current->value);
      free(current);
    }
  }
  free(table->entries);
  free(table);
}
