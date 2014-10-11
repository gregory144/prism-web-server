#ifndef HTTP_ATOMIC_INT_H
#define HTTP_ATOMIC_INT_H

#include <uv.h>

typedef struct {

  uv_mutex_t mutex;

  int value;

} atomic_int_t;

atomic_int_t * atomic_int_init(atomic_int_t * i);

int atomic_int_value(atomic_int_t * i);

int atomic_int_increment(atomic_int_t * i);
int atomic_int_decrement(atomic_int_t * i);

void atomic_int_free(atomic_int_t * i);

#endif

