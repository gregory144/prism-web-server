#include <stdlib.h>
#include <stdio.h>
#include <check.h>
#include <limits.h>

#include "../util/util.c"
#include "../util/multimap.c"
#include "../huffman/huffman.c"

#include "hpack.c"
#include "circular_buffer.c"

void setup() {
}

void teardown() {
}

START_TEST(test_hpack_decode_quantity_in_8bit_prefix) {
  unsigned char buf[] = { 0x2a };
  hpack_decode_quantity_result_t decoded;
  hpack_decode_quantity(buf, 1, 0, &decoded);
  ck_assert_int_eq(decoded.value, 42);
  ck_assert_int_eq(decoded.num_bytes, 1);
} END_TEST

START_TEST(test_hpack_decode_quantity_in_5bit_prefix) {
  unsigned char buf[] = { 0xea };
  hpack_decode_quantity_result_t decoded;
  hpack_decode_quantity(buf, 1, 3, &decoded);
  ck_assert_int_eq(decoded.value, 10);
  ck_assert_int_eq(decoded.num_bytes, 1);
} END_TEST

START_TEST(test_hpack_decode_large_quantity_in_5bit_prefix) {
  unsigned char buf[] = { 0xff, 0x9a, 0x0a };
  hpack_decode_quantity_result_t decoded;
  hpack_decode_quantity(buf, 3, 3, &decoded);
  ck_assert_int_eq(decoded.value, 1337);
  ck_assert_int_eq(decoded.num_bytes, 3);
} END_TEST

START_TEST(test_hpack_encode_10_in_5bit_prefix) {
  unsigned char buf[1024] = {0};
  size_t size = hpack_encode_quantity(buf, 3, 10);
  ck_assert_int_eq(size, 1);
  ck_assert_int_eq(buf[0], 0xA);
} END_TEST

START_TEST(test_hpack_encode_10_in_5bit_prefix_already_filled_in) {
  unsigned char buf[1024] = {0};
  buf[0] = 0xE0;
  size_t size = hpack_encode_quantity(buf, 3, 10);
  ck_assert_int_eq(size, 1);
  ck_assert_int_eq(buf[0], 0xEA);
} END_TEST

START_TEST(test_hpack_encode_1337_quantity_in_5bit_prefix) {
  unsigned char buf[1024] = {0};
  size_t size = hpack_encode_quantity(buf, 3, 1337);
  ck_assert_int_eq(size, 3);
  ck_assert_int_eq(buf[0], 0x1F);
  ck_assert_int_eq(buf[1], 0x9A);
  ck_assert_int_eq(buf[2], 0x0A);
} END_TEST

START_TEST(test_hpack_encode_42_quantity_in_8bit_prefix) {
  unsigned char buf[1024] = {0};
  size_t size = hpack_encode_quantity(buf, 8, 42);
  ck_assert_int_eq(size, 1);
  ck_assert_int_eq(buf[1], 0x2A);
} END_TEST

START_TEST(test_hpack_encode_and_decode_smaller_numbers) {
  unsigned char buf[1024] = {0};
  size_t i;
  for (i = 0; i < INT_MAX; i += 1000000) {
    hpack_encode_quantity(buf, 0, i);
    hpack_decode_quantity_result_t decoded;
    hpack_decode_quantity(buf, 1024, 0, &decoded);
    ck_assert_int_eq(decoded.value, i);
  }
} END_TEST

START_TEST(test_hpack_encode_and_decode_small_numbers) { // 1 - 2^16
  unsigned char buf[1024] = {0};
  size_t i;
  for (i = 0; i < 2 << 15; i++) {
    hpack_encode_quantity(buf, 0, i);
    hpack_decode_quantity_result_t decoded;
    hpack_decode_quantity(buf, 1024, 0, &decoded);
    ck_assert_int_eq(decoded.value, i);
  }
} END_TEST

START_TEST(test_hpack_encode_and_decode_large_numbers) {
  unsigned char buf[1024] = {0};
  int i;
  size_t value = 1;
  int multiplier = 2;
  int addand = 6;
  for (i = 0; i < 25; i++) {
    hpack_encode_quantity(buf, 0, value);
    hpack_decode_quantity_result_t decoded;
    hpack_decode_quantity(buf, 1024, 0, &decoded);
    ck_assert_int_eq(decoded.value, value);
    value = value * multiplier + addand;
  }
} END_TEST

Suite * hpack_suite() {
  Suite *s = suite_create("hpack");

  TCase *tc_decoder = tcase_create("decoder");
  tcase_add_checked_fixture(tc_decoder, setup, teardown);

  tcase_add_test(tc_decoder, test_hpack_decode_quantity_in_8bit_prefix);
  tcase_add_test(tc_decoder, test_hpack_decode_quantity_in_5bit_prefix);
  tcase_add_test(tc_decoder, test_hpack_decode_large_quantity_in_5bit_prefix);

  tcase_add_test(tc_decoder, test_hpack_encode_10_in_5bit_prefix);
  tcase_add_test(tc_decoder, test_hpack_encode_10_in_5bit_prefix_already_filled_in);
  tcase_add_test(tc_decoder, test_hpack_encode_1337_quantity_in_5bit_prefix);
  tcase_add_test(tc_decoder, test_hpack_encode_42_quantity_in_8bit_prefix);

  tcase_add_test(tc_decoder, test_hpack_encode_and_decode_small_numbers);
  tcase_add_test(tc_decoder, test_hpack_encode_and_decode_smaller_numbers);
  tcase_add_test(tc_decoder, test_hpack_encode_and_decode_large_numbers);

  suite_add_tcase(s, tc_decoder);

  return s;
}

int main () {
  Suite *s = hpack_suite();
  SRunner *sr = srunner_create(s);
  srunner_run_all(sr, CK_NORMAL);
  int number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
