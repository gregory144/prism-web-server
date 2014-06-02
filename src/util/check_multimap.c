#include <stdlib.h>
#include <stdio.h>
#include <check.h>

#include "multimap.c"

multimap_t * map;

void setup_mm_strings()
{
  map = multimap_init_with_string_keys();
}

void teardown_mm_strings()
{
  multimap_free(map, free, free);
}

START_TEST(test_mm_strings_put_and_get)
{
  ck_assert(multimap_put(map, strdup("k1"), strdup("v1")));
  multimap_values_t * values = multimap_get(map, "k1");
  ck_assert_str_eq(values->value, "v1");
  ck_assert(!values->next);
  ck_assert_uint_eq(1, multimap_size(map));
}
END_TEST

START_TEST(test_mm_strings_put_and_get_multiple)
{
  ck_assert(multimap_put(map, strdup("k1"), strdup("v1")));
  ck_assert(multimap_put(map, strdup("k1"), strdup("v2")));
  ck_assert(multimap_put(map, strdup("k1"), strdup("v3")));
  multimap_values_t * values = multimap_get(map, "k1");
  ck_assert(!!values->next);
  ck_assert(!!values->next->next);
  ck_assert(!values->next->next->next);
  ck_assert_str_eq(values->value, "v1");
  ck_assert_str_eq(values->next->value, "v2");
  ck_assert_str_eq(values->next->next->value, "v3");
  ck_assert_uint_eq(3, multimap_size(map));
}
END_TEST

START_TEST(test_mm_strings_put_and_grow)
{
  int i, j;
  char keys[1000][10];

  for (i = 0; i < 1000; i++) {
    snprintf(keys[i], 10, "%d", i);
    ck_assert(multimap_put(map, strdup(keys[i]), strdup(keys[i])));

    for (j = 0; j < i; j++) {
      multimap_values_t * values = multimap_get(map, keys[j]);
      ck_assert(values != NULL);
      ck_assert_str_eq(keys[j], values->value);
    }

    ck_assert_uint_eq(i + 1, multimap_size(map));
  }
}
END_TEST

START_TEST(test_mm_strings_put_and_remove)
{
  ck_assert(multimap_put(map, strdup("k1"), strdup("v1")));
  multimap_values_t * values = multimap_get(map, "k1");
  ck_assert_str_eq(values->value, "v1");
  ck_assert(!values->next);
  ck_assert_uint_eq(1, multimap_size(map));

  multimap_remove(map, "k1", free, free);
  ck_assert_uint_eq(0, multimap_size(map));

  values = multimap_get(map, "k1");
  ck_assert(!values);

}
END_TEST

START_TEST(test_mm_strings_put_and_remove_multiple)
{
  ck_assert(multimap_put(map, strdup("k1"), strdup("v1")));
  ck_assert(multimap_put(map, strdup("k1"), strdup("v2")));
  multimap_values_t * values = multimap_get(map, "k1");
  ck_assert(!!values);

  multimap_remove(map, "k1", free, free);
  ck_assert_uint_eq(0, multimap_size(map));

  values = multimap_get(map, "k1");
  ck_assert(!values);

}
END_TEST

void setup_mm_ints()
{
  map = multimap_init_with_int_keys();
}

void teardown_mm_ints()
{
  multimap_free(map, free, free);
}

START_TEST(test_mm_ints_put_and_get)
{
  long * k1 = malloc(sizeof(long));
  * k1 = 10;

  ck_assert(multimap_put(map, k1, strdup("v1")));
  multimap_values_t * values = multimap_get(map, k1);
  ck_assert_str_eq(values->value, "v1");
  ck_assert(!values->next);
  ck_assert_uint_eq(1, multimap_size(map));
}
END_TEST

START_TEST(test_mm_ints_put_and_get_multiple)
{
  long * k1 = malloc(sizeof(long));
  * k1 = 10;

  ck_assert(multimap_put(map, k1, strdup("v1")));
  ck_assert(multimap_put(map, k1, strdup("v2")));
  ck_assert(multimap_put(map, k1, strdup("v3")));
  multimap_values_t * values = multimap_get(map, k1);
  ck_assert(!!values->next);
  ck_assert(!!values->next->next);
  ck_assert(!values->next->next->next);
  ck_assert_str_eq(values->value, "v1");
  ck_assert_str_eq(values->next->value, "v2");
  ck_assert_str_eq(values->next->next->value, "v3");
  ck_assert_uint_eq(3, multimap_size(map));
}
END_TEST

START_TEST(test_mm_ints_put_and_grow)
{
  long i, j;

  for (i = 0; i < 300; i++) {
    long * i_key = malloc(sizeof(long));
    * i_key = i;
    long * i_value = malloc(sizeof(long));
    * i_value = i;

    ck_assert(multimap_put(map, i_key, i_value));

    for (j = 0; j <= i; j++) {
      long * j_key = malloc(sizeof(long));
      * j_key = j;

      multimap_values_t * values = multimap_get(map, j_key);
      ck_assert(values != NULL);
      ck_assert(values->value != NULL);
      ck_assert_int_eq(j, * (long *)values->value);

      free(j_key);
    }

    ck_assert_uint_eq(i + 1, multimap_size(map));
  }
}
END_TEST

START_TEST(test_mm_ints_put_and_remove)
{
  long * k1 = malloc(sizeof(long));
  * k1 = 10;

  ck_assert(multimap_put(map, k1, strdup("v1")));
  multimap_values_t * values = multimap_get(map, k1);
  ck_assert_str_eq(values->value, "v1");
  ck_assert(!values->next);
  ck_assert_uint_eq(1, multimap_size(map));

  multimap_remove(map, k1, free, free);
  ck_assert_uint_eq(0, multimap_size(map));

  values = multimap_get(map, k1);
  ck_assert(!values);

}
END_TEST

START_TEST(test_mm_ints_put_and_remove_multiple)
{
  long * k1 = malloc(sizeof(long));
  * k1 = 10;

  ck_assert(multimap_put(map, k1, strdup("v1")));
  ck_assert(multimap_put(map, k1, strdup("v2")));
  multimap_values_t * values = multimap_get(map, k1);
  ck_assert(!!values);

  multimap_remove(map, k1, free, free);
  ck_assert_uint_eq(0, multimap_size(map));

  values = multimap_get(map, k1);
  ck_assert(!values);

}
END_TEST

Suite * suite()
{
  Suite * s = suite_create("multimap");

  TCase * tc_mm_strings = tcase_create("multimap with string keys");
  tcase_add_checked_fixture(tc_mm_strings, setup_mm_strings, teardown_mm_strings);

  tcase_add_test(tc_mm_strings, test_mm_strings_put_and_get);
  tcase_add_test(tc_mm_strings, test_mm_strings_put_and_get_multiple);
  tcase_add_test(tc_mm_strings, test_mm_strings_put_and_grow);
  tcase_add_test(tc_mm_strings, test_mm_strings_put_and_remove);
  tcase_add_test(tc_mm_strings, test_mm_strings_put_and_remove_multiple);

  suite_add_tcase(s, tc_mm_strings);

  TCase * tc_mm_ints = tcase_create("multimap with integer keys");
  tcase_add_checked_fixture(tc_mm_ints, setup_mm_ints, teardown_mm_ints);

  tcase_add_test(tc_mm_ints, test_mm_ints_put_and_get);
  tcase_add_test(tc_mm_ints, test_mm_ints_put_and_get_multiple);
  tcase_add_test(tc_mm_ints, test_mm_ints_put_and_grow);
  tcase_add_test(tc_mm_ints, test_mm_ints_put_and_remove);
  tcase_add_test(tc_mm_ints, test_mm_ints_put_and_remove_multiple);

  suite_add_tcase(s, tc_mm_ints);

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
