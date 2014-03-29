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
  table->buckets= calloc(initial_size, sizeof(multimap_entry_t));
  if (table->buckets == NULL) {
    return NULL;
  }
  table->hash_func = hash_func;
  table->cmp_key_func = cmp_key_func;
  table->size = 0;
  table->capacity = initial_size;
  return table;
}

void multimap_values_free(multimap_values_t* values, free_func_t free_key, free_func_t free_value) {
  // don't free the first value container - it will be free'd when the entry is free'd
  free_key(values->key);
  free_value(values->value);

  multimap_values_t* current = values->next;
  while (current) {
    multimap_values_t* next = current->next;
    free_key(current->key);
    free_value(current->value);
    free(current);
    current = next;
  }
}

void multimap_free(multimap_t* table, free_func_t free_key, free_func_t free_value) {
  size_t i;
  for (i = 0; i < table->capacity; i++) {
    multimap_entry_t* entry = table->buckets[i];
    multimap_entry_t* current;
    while (entry) {
      current = entry;
      entry = entry->next;
      multimap_values_free(current->values, free_key, free_value);
      free(current);
    }
  }
  free(table->buckets);
  free(table);
}

size_t hash_key(multimap_t* table, void* key) {
  size_t hash_value = table->hash_func(key);
  return hash_value % table->capacity;
}

multimap_entry_t* multimap_get_entry(multimap_t* table, void* key) {
  size_t hash_value = hash_key(table, key);
  multimap_entry_t* current;
  for (current = table->buckets[hash_value]; current != NULL;
      current = current->next) {
    if (table->cmp_key_func(key, current->key) == 0) {
      // found
      return current;
    }
  }
  return NULL;
}

multimap_values_t* multimap_get(multimap_t* table, void* key) {
  multimap_entry_t* entry = multimap_get_entry(table, key);
  if (entry) {
    return entry->values;
  }
  return NULL;
}

bool multimap_grow(multimap_t* table) {
  // TODO
  abort();
  size_t new_size = table->capacity * 2;
  multimap_entry_t* new_buckets = calloc(new_size,
      sizeof(multimap_entry_t));
  if (new_buckets == NULL) {
    return false;
  }
  // iterate through all entries in table and re-insert into
  // new table
  for (size_t i = 0; i < table->capacity; i++) {
    multimap_entry_t *current = table->buckets[i];
    for (; current != NULL; current = current->next) {
      // TODO
    }
  }
  return true;
} 

/**
 * Adds the given key and value to the end of the list of values
 * (maintains order)
 */
void multimap_values_add(multimap_values_t* values, void* key, void* value) {
  multimap_values_t* new_value = malloc(sizeof(multimap_values_t));
  new_value->key = key;
  new_value->value = value;
  new_value->next = NULL;

  while(values->next) {
    values = values->next;
  }
  values->next = new_value;
}

/**
 * Adds a key/value to the map
 */
bool multimap_put(multimap_t* table, void* key, void* value) {
  size_t hash_value = hash_key(table, key);
  multimap_entry_t* entry;
  if ((entry = multimap_get_entry(table, key)) == NULL) {
    // not found

    // grow the table if necessary
    if ((table->size + 1.0) / table->capacity > 0.75) {
      if (!multimap_grow(table)) {
        return false;
      }
    }

    // create a new entry and put it in the table
    entry = malloc(sizeof(multimap_entry_t));
    entry->values = &entry->first_value;
    if (entry == NULL) {
      return false;
    }
    entry->key = key;
    entry->next = table->buckets[hash_value];
    table->buckets[hash_value] = entry;

    entry->size = 1;

    // set up the first entry
    entry->values->key = key;
    entry->values->value = value;
    entry->values->next = NULL;
  } else {
    multimap_values_add(entry->values, key, value);
    entry->size++;
  }
  table->size++;
  return true;
}

void multimap_remove(multimap_t* table, void* key, free_func_t free_key, free_func_t free_value) {
  size_t hash_value = hash_key(table, key);
  multimap_entry_t* current;
  multimap_entry_t* prev = NULL;
  for (current = table->buckets[hash_value]; current != NULL;
      current = current->next) {
    if (table->cmp_key_func(key, current->key) == 0) {
      if (prev) {
        prev->next = current->next;
      } else {
        table->buckets[hash_value] = current->next;
      }
      multimap_values_free(current->values, free_key, free_value);
      table->size -= current->size;;
      free(current);
      return;
    }
  }
}

void multimap_iterator_init(multimap_iter_t* iter, multimap_t* table) {
  iter->entry = NULL;
  iter->values = NULL;
  iter->next = NULL;
  iter->index = 0;
  iter->table = table;
}

bool multimap_iterate(multimap_iter_t* iter) {
  multimap_t* table = iter->table;
  multimap_entry_t* entry = iter->entry;
  multimap_values_t* value_container = iter->values;
  if (value_container && value_container->next) {
    value_container = value_container->next;
  } else if (entry && entry->next) {
    entry = entry->next;
    value_container = NULL;
  } else {
    value_container = NULL;
    do {
      entry = table->buckets[iter->index];
      iter->index++;
    } while (!entry && iter->index < table->capacity);
  }
  iter->entry = entry;
  if (value_container) {
    iter->values = value_container;
  } else if (entry && entry->values) {
    iter->values = entry->values;
  } else {
    iter->values = NULL;
  }
  if (iter->values) {
    iter->key = iter->values->key;
    iter->value = iter->values->value;
  }
  return iter->values != NULL;
}

