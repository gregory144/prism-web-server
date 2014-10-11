#include "config.h"

#include <stdlib.h>
#include <stdio.h>

#include <uv.h>

#include "atomic_int.h"

atomic_int_t * atomic_int_init(atomic_int_t * i)
{
  uv_mutex_init(&i->mutex);

  i->value = 0;

  return i;
}

int atomic_int_value(atomic_int_t * i)
{
  uv_mutex_lock(&i->mutex);

  int value = i->value;

  uv_mutex_unlock(&i->mutex);

  return value;
}

int atomic_int_increment(atomic_int_t * i)
{
  uv_mutex_lock(&i->mutex);

  i->value++;
  int value = i->value;

  uv_mutex_unlock(&i->mutex);

  return value;
}

int atomic_int_decrement(atomic_int_t * i)
{
  uv_mutex_lock(&i->mutex);

  i->value--;
  int value = i->value;

  uv_mutex_unlock(&i->mutex);

  return value;
}

void atomic_int_free(atomic_int_t * i)
{
  uv_mutex_destroy(&i->mutex);
}



