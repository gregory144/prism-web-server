#include <stdlib.h>
#include <stdio.h>
#include <check.h>

#include "blocking_queue.c"

blocking_queue_t * q;

void setup()
{
  q = blocking_queue_init();
}

void teardown()
{
  blocking_queue_free(q);
}

START_TEST(test_blocking_queue_push)
{
  blocking_queue_push(q, "100");
  char * top = blocking_queue_try_pop(q);
  ck_assert_str_eq(top, "100");
}
END_TEST

START_TEST(test_blocking_queue_push_multiple)
{
  blocking_queue_push(q, "100");
  blocking_queue_push(q, "150");
  blocking_queue_push(q, "200");
  char * top = blocking_queue_try_pop(q);
  ck_assert_str_eq(top, "100");
  top = blocking_queue_try_pop(q);
  ck_assert_str_eq(top, "150");
  top = blocking_queue_try_pop(q);
  ck_assert_str_eq(top, "200");
}
END_TEST

START_TEST(test_blocking_queue_push_after_pop)
{
  blocking_queue_push(q, "100");
  blocking_queue_push(q, "150");
  char * top = blocking_queue_try_pop(q);
  ck_assert_str_eq(top, "100");
  blocking_queue_push(q, "125");
  top = blocking_queue_try_pop(q);
  ck_assert_str_eq(top, "150");
  top = blocking_queue_try_pop(q);
  ck_assert_str_eq(top, "125");
}
END_TEST

START_TEST(test_blocking_queue_try_pop_empty)
{
  char * top = blocking_queue_try_pop(q);
  ck_assert(top == NULL);
}
END_TEST

Suite * blocking_queue_suite()
{
  Suite * s = suite_create("blocking_queue");

  TCase * tc_q = tcase_create("blocking_queue");
  tcase_add_checked_fixture(tc_q, setup, teardown);

  tcase_add_test(tc_q, test_blocking_queue_push);
  tcase_add_test(tc_q, test_blocking_queue_push_multiple);
  tcase_add_test(tc_q, test_blocking_queue_push_after_pop);

  tcase_add_test(tc_q, test_blocking_queue_try_pop_empty);

  suite_add_tcase(s, tc_q);

  return s;
}

int main()
{
  int number_failed;
  Suite * s = blocking_queue_suite();
  SRunner * sr = srunner_create(s);
  srunner_run_all(sr, CK_NORMAL);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
