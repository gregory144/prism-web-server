#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <check.h>

#include "hash_table.c"

hash_table_t * ht;

void setup_ht_strings()
{
  ht = hash_table_init_with_string_keys(free);
}

void teardown_ht_strings()
{
  hash_table_free(ht);
}

START_TEST(test_ht_strings_put_and_get)
{
  ck_assert(hash_table_put(ht, strdup("k1"), strdup("v1")));
  void * value = hash_table_get(ht, "k1");
  ck_assert_str_eq(value, "v1");
  ck_assert_uint_eq(1, hash_table_size(ht));
}
END_TEST

START_TEST(test_ht_strings_put_and_get_multiple)
{

  char * k1 = strdup("k1");
  char * k2 = strdup("k1");
  char * k3 = strdup("k1");

  char * v1 = strdup("v1");
  char * v2 = strdup("v2");
  char * v3 = strdup("v3");

  ck_assert(hash_table_put(ht, k1, v1));
  ck_assert(hash_table_put(ht, k2, v2));
  ck_assert(hash_table_put(ht, k3, v3));
  void * value = hash_table_get(ht, "k1");
  ck_assert_str_eq(value, "v3");
  ck_assert_uint_eq(1, hash_table_size(ht));
}
END_TEST

START_TEST(test_ht_strings_put_and_grow)
{
  int i, j;
  char keys[500][10];

  for (i = 0; i < 500; i++) {
    snprintf(keys[i], 10, "%d", i);
    ck_assert(hash_table_put(ht, strdup(keys[i]), strdup(keys[i])));

    for (j = 0; j < i; j++) {
      void * value = hash_table_get(ht, keys[j]);
      ck_assert(value != NULL);
      ck_assert_str_eq(keys[j], value);
    }

    ck_assert_uint_eq(i + 1, hash_table_size(ht));
  }
}
END_TEST

START_TEST(test_ht_strings_put_and_remove)
{
  char * k1 = strdup("k1");
  char * v1 = strdup("v1");

  ck_assert(hash_table_put(ht, k1, v1));
  void * value = hash_table_get(ht, "k1");
  ck_assert_str_eq(value, "v1");
  ck_assert_uint_eq(1, hash_table_size(ht));

  value = hash_table_remove(ht, "k1");
  free(value);
  ck_assert_uint_eq(0, hash_table_size(ht));

  value = hash_table_get(ht, "k1");
  ck_assert(!value);

}
END_TEST

void setup_ht_ints()
{
  ht = hash_table_init_with_int_keys(free);
}

void teardown_ht_ints()
{
  hash_table_free(ht);
}

START_TEST(test_ht_ints_put_and_get)
{
  long * k1 = malloc(sizeof(long));
  * k1 = 10;

  ck_assert(hash_table_put(ht, k1, strdup("v1")));
  void * value = hash_table_get(ht, k1);
  ck_assert_str_eq(value, "v1");
  ck_assert_uint_eq(1, hash_table_size(ht));
}
END_TEST

START_TEST(test_ht_ints_put_and_get_multiple)
{
  long * k1 = malloc(sizeof(long));
  * k1 = 10;
  long * k2 = malloc(sizeof(long));
  * k2 = 10;
  long * k3 = malloc(sizeof(long));
  * k3 = 10;

  char * v1 = strdup("v1");
  char * v2 = strdup("v2");
  char * v3 = strdup("v3");

  ck_assert(hash_table_put(ht, k1, v1));
  ck_assert(hash_table_put(ht, k2, v2));
  ck_assert(hash_table_put(ht, k3, v3));
  long k = 10;
  void * value = hash_table_get(ht, &k);
  ck_assert_str_eq(value, "v3");
  ck_assert_uint_eq(1, hash_table_size(ht));

}
END_TEST

START_TEST(test_ht_ints_put_and_grow)
{
  long i, j;

  for (i = 0; i < 300; i++) {
    long * i_key = malloc(sizeof(long));
    * i_key = i;
    long * i_value = malloc(sizeof(long));
    * i_value = i;

    ck_assert(hash_table_put(ht, i_key, i_value));

    for (j = 0; j <= i; j++) {
      long * j_key = malloc(sizeof(long));
      * j_key = j;

      void * value = hash_table_get(ht, j_key);
      ck_assert(value != NULL);
      ck_assert_int_eq(j, * (long *)value);

      free(j_key);
    }

    ck_assert_uint_eq(i + 1, hash_table_size(ht));
  }
}
END_TEST

START_TEST(test_ht_ints_put_and_remove)
{
  long * k1 = malloc(sizeof(long));
  * k1 = 10;

  ck_assert(hash_table_put(ht, k1, strdup("v1")));
  void * value = hash_table_get(ht, k1);
  ck_assert_str_eq(value, "v1");
  ck_assert_uint_eq(1, hash_table_size(ht));

  hash_table_remove(ht, k1);
  ck_assert_uint_eq(0, hash_table_size(ht));

  value = hash_table_get(ht, k1);
  ck_assert(!value);

}
END_TEST

Suite * suite()
{
  Suite * s = suite_create("hash table");

  TCase * tc_ht_strings = tcase_create("hash table with string keys");
  tcase_add_checked_fixture(tc_ht_strings, setup_ht_strings, teardown_ht_strings);

  tcase_add_test(tc_ht_strings, test_ht_strings_put_and_get);
  tcase_add_test(tc_ht_strings, test_ht_strings_put_and_get_multiple);
  tcase_add_test(tc_ht_strings, test_ht_strings_put_and_grow);
  tcase_add_test(tc_ht_strings, test_ht_strings_put_and_remove);

  suite_add_tcase(s, tc_ht_strings);

  TCase * tc_ht_ints = tcase_create("hash table with integer keys");
  tcase_add_checked_fixture(tc_ht_ints, setup_ht_ints, teardown_ht_ints);

  tcase_add_test(tc_ht_ints, test_ht_ints_put_and_get);
  tcase_add_test(tc_ht_ints, test_ht_ints_put_and_get_multiple);
  tcase_add_test(tc_ht_ints, test_ht_ints_put_and_grow);
  tcase_add_test(tc_ht_ints, test_ht_ints_put_and_remove);

  suite_add_tcase(s, tc_ht_ints);

  return s;
}

int main()
{
  Suite * s = suite();
  SRunner * sr = srunner_create(s);
  srunner_run_all(sr, CK_NORMAL);
  int number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
