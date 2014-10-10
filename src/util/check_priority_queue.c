#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <check.h>

#include "priority_queue.c"

priority_queue_t * pq;

void setup()
{
  pq = priority_queue_init(10);
}

void teardown()
{
  priority_queue_free(pq);
}

START_TEST(test_priority_queue_push)
{
  priority_queue_push(pq, 100, "100");
  char * top = priority_queue_pop(pq);
  ck_assert_str_eq(top, "100");
}
END_TEST

START_TEST(test_priority_queue_push_higher_priority)
{
  priority_queue_push(pq, 100, "100");
  priority_queue_push(pq, 50, "50");
  char * top = priority_queue_pop(pq);
  ck_assert_str_eq(top, "50");
  top = priority_queue_pop(pq);
  ck_assert_str_eq(top, "100");
}
END_TEST

START_TEST(test_priority_queue_push_lower_priority)
{
  priority_queue_push(pq, 100, "100");
  priority_queue_push(pq, 150, "150");
  char * top = priority_queue_pop(pq);
  ck_assert_str_eq(top, "100");
  top = priority_queue_pop(pq);
  ck_assert_str_eq(top, "150");
}
END_TEST

START_TEST(test_priority_queue_push_in_middle)
{
  priority_queue_push(pq, 100, "100");
  priority_queue_push(pq, 150, "150");
  priority_queue_push(pq, 125, "125");
  char * top = priority_queue_pop(pq);
  ck_assert_str_eq(top, "100");
  top = priority_queue_pop(pq);
  ck_assert_str_eq(top, "125");
  top = priority_queue_pop(pq);
  ck_assert_str_eq(top, "150");
}
END_TEST

START_TEST(test_priority_queue_push_after_pop)
{
  priority_queue_push(pq, 100, "100");
  priority_queue_push(pq, 150, "150");
  char * top = priority_queue_pop(pq);
  ck_assert_str_eq(top, "100");
  priority_queue_push(pq, 125, "125");
  top = priority_queue_pop(pq);
  ck_assert_str_eq(top, "125");
  top = priority_queue_pop(pq);
  ck_assert_str_eq(top, "150");
}
END_TEST

START_TEST(test_priority_queue_modify_priority)
{
  priority_queue_entry_t * entry = priority_queue_push(pq, 100, "100");
  priority_queue_modify_priority(pq, entry, 125);
  char * top = priority_queue_pop(pq);
  ck_assert_str_eq(top, "100");
}
END_TEST

START_TEST(test_priority_queue_modify_priority_changes_order)
{
  priority_queue_entry_t * entry = priority_queue_push(pq, 100, "100");
  priority_queue_push(pq, 150, "150");
  priority_queue_modify_priority(pq, entry, 175);
  char * top = priority_queue_pop(pq);
  ck_assert_str_eq(top, "150");
  top = priority_queue_pop(pq);
  ck_assert_str_eq(top, "100");
}
END_TEST

START_TEST(test_priority_queue_pop_empty)
{
  char * top = priority_queue_pop(pq);
  ck_assert(top == NULL);
}
END_TEST

START_TEST(test_priority_queue_size)
{
  ck_assert_uint_eq(0, priority_queue_size(pq));
  priority_queue_push(pq, 100, "100");
  ck_assert_uint_eq(1, priority_queue_size(pq));
  priority_queue_push(pq, 150, "150");
  ck_assert_uint_eq(2, priority_queue_size(pq));
  priority_queue_push(pq, 125, "125");
  ck_assert_uint_eq(3, priority_queue_size(pq));
  priority_queue_pop(pq);
  ck_assert_uint_eq(2, priority_queue_size(pq));
  priority_queue_pop(pq);
  ck_assert_uint_eq(1, priority_queue_size(pq));
  priority_queue_pop(pq);
  ck_assert_uint_eq(0, priority_queue_size(pq));
}
END_TEST

Suite * priority_queue_suite()
{
  Suite * s = suite_create("priority_queue");

  TCase * tc_pq = tcase_create("priority_queue");
  tcase_add_checked_fixture(tc_pq, setup, teardown);

  tcase_add_test(tc_pq, test_priority_queue_push);
  tcase_add_test(tc_pq, test_priority_queue_push_higher_priority);
  tcase_add_test(tc_pq, test_priority_queue_push_lower_priority);
  tcase_add_test(tc_pq, test_priority_queue_push_in_middle);
  tcase_add_test(tc_pq, test_priority_queue_push_after_pop);

  tcase_add_test(tc_pq, test_priority_queue_modify_priority);
  tcase_add_test(tc_pq, test_priority_queue_modify_priority_changes_order);

  tcase_add_test(tc_pq, test_priority_queue_pop_empty);

  tcase_add_test(tc_pq, test_priority_queue_size);

  suite_add_tcase(s, tc_pq);

  return s;
}

int main()
{
  int number_failed;
  Suite * s = priority_queue_suite();
  SRunner * sr = srunner_create(s);
  srunner_run_all(sr, CK_NORMAL);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
