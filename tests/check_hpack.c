#include <stdlib.h>
#include <check.h>

#include "../src/hpack.h"

void setup() {
}

void teardown() {
}

START_TEST(test_hpack_decode) {
  ck_assert_int_eq(hpack_add(1, 1), 2);
  ck_assert_int_eq(hpack_add(1, 2), 2);
} END_TEST

Suite * hpack_suite() {
  Suite *s = suite_create("hpack");

  TCase *tc_decoder = tcase_create("decoder");
  tcase_add_checked_fixture(tc_decoder, setup, teardown);
  tcase_add_test(tc_decoder, test_hpack_decode);
  suite_add_tcase(s, tc_decoder);

  return s;
}

int main () {
  int number_failed;
  Suite *s = hpack_suite();
  SRunner *sr = srunner_create(s);
  srunner_run_all(sr, CK_NORMAL);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
