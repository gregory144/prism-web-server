#include <stdlib.h>
#include <check.h>

#include "../src/hpack.h"

void setup() {
}

void teardown() {
}

START_TEST(test_hpack_decode_int_in_8bit_prefix) {
  char buf[] = { 0x2a };
  int decoded = hpack_decode_int(buf, 1, 0);
  ck_assert_int_eq(decoded, 42);
} END_TEST

START_TEST(test_hpack_decode_int_in_5bit_prefix) {
  char buf[] = { 0xea };
  int decoded = hpack_decode_int(buf, 1, 3);
  ck_assert_int_eq(decoded, 10);
} END_TEST

START_TEST(test_hpack_decode_large_int_in_5bit_prefix) {
  char buf[] = { 0xff, 0x9a, 0x0a };
  int decoded = hpack_decode_int(buf, 3, 3);
  ck_assert_int_eq(decoded, 1337);
} END_TEST

Suite * hpack_suite() {
  Suite *s = suite_create("hpack");

  TCase *tc_decoder = tcase_create("decoder");
  tcase_add_checked_fixture(tc_decoder, setup, teardown);
  tcase_add_test(tc_decoder, test_hpack_decode_int_in_8bit_prefix);
  tcase_add_test(tc_decoder, test_hpack_decode_int_in_5bit_prefix);
  tcase_add_test(tc_decoder, test_hpack_decode_large_int_in_5bit_prefix);
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
