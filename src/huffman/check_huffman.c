#include <stdlib.h>
#include <stdio.h>
#include <check.h>

#include "../util/util.c"

#include "huffman.c"

void check_encoded_val(unsigned char expected[], size_t expected_length, unsigned char result[], size_t length) {
  ck_assert_int_eq(expected_length, length);
  size_t l = length + 1;
  unsigned char expected_cstr[l];
  memcpy(expected_cstr, expected, length);
  expected_cstr[length] = 0;
  unsigned char result_cstr[l];
  memcpy(result_cstr, result, length);
  result_cstr[length] = 0;
  size_t i = 0;
  for (i = 0; i < expected_length; i++) {
    ck_assert_uint_eq(expected_cstr[i], result_cstr[i]);
  }
}

void setup() {
}

void teardown() {
}

START_TEST(test_huffman_decode_single_char) {
  uint8_t buf[] = { 0xed }; // 0b11101101 (66/B)
  huffman_result_t result;
  ck_assert(huffman_decode(buf, 1, &result));
  ck_assert_int_eq(1, result.length);
  ck_assert_str_eq("B", (char*)result.value);
} END_TEST

START_TEST(test_huffman_decode_single_char_with_eos) {
  uint8_t buf[] = { 0x2f }; // 0b00101111 (50/2)
  huffman_result_t result;
  ck_assert(huffman_decode(buf, 1, &result));
  ck_assert_int_eq(1, result.length);
  ck_assert_str_eq("2", (char*)result.value);
} END_TEST

START_TEST(test_huffman_decode_two_chars) {
  uint8_t buf[] = { 0xd9, 0xf6 }; // 0b1101100111110110 (78/N, 81/Q)
  huffman_result_t result;
  ck_assert(huffman_decode(buf, 2, &result));
  ck_assert_int_eq(2, result.length);
  ck_assert_str_eq("NQ", (char*)result.value);
} END_TEST

START_TEST(test_huffman_decode_two_chars_with_eos) {
  uint8_t buf[] = { 0xd3, 0xab }; // 0b1101 0011 1010 1011 (70/F, 71/G)
  huffman_result_t result;
  ck_assert(huffman_decode(buf, 2, &result));
  ck_assert_int_eq(2, result.length);
  ck_assert_str_eq("FG", (char*)result.value);
} END_TEST

START_TEST(test_huffman_encode_single_8bit_char) {
  char buf[] = { 'E' };
  uint8_t encoded[] = { 0xef };

  huffman_result_t result;
  ck_assert(huffman_encode(buf, 1, &result));
  check_encoded_val(encoded, 1, result.value, result.length);
} END_TEST

START_TEST(test_huffman_encode_single_5bit_char) {
  char buf[] = { 't' };
  uint8_t encoded[] = { 0x77 }; // padded with 1s

  huffman_result_t result;
  ck_assert(huffman_encode(buf, 1, &result));
  check_encoded_val(encoded, 1, result.value, result.length);
} END_TEST

START_TEST(test_huffman_encode_single_9bit_char) {
  char buf[] = { 'Z' };
  uint8_t encoded[] = { 0xfd, 0xff }; // padded with 1s

  huffman_result_t result;
  ck_assert(huffman_encode(buf, 1, &result));
  check_encoded_val(encoded, 2, result.value, result.length);
} END_TEST

START_TEST(test_huffman_encode_12bit_out) {
  char buf[] = { '5', '4' };
  uint8_t encoded[] = { 0x86, 0x0f }; // padded with 1s
  huffman_result_t result;
  ck_assert(huffman_encode(buf, 2, &result));
  check_encoded_val(encoded, 2, result.value, result.length);
} END_TEST

START_TEST(test_huffman_encode_longer_string) {
  char buf[] = "Hello World!";
  uint8_t encoded[] = {
    0xf9, 0x2e, 0xcb, 0x1a, 0x6f, 0xcb, 0x70, 0xb2, 0x9f, 0xfe, 0x7f
  }; // padded with 1s
  huffman_result_t result;
  ck_assert(huffman_encode(buf, 12, &result));
  check_encoded_val(encoded, 11, result.value, result.length);
} END_TEST

START_TEST(test_huffman_encode_date) {
  char buf[] = "Wed, 05 Mar 2014 09:20:58 GMT";
  uint8_t encoded[] = {
    0xfc, 0xae, 0x9c, 0xa6, 0x08, 0x4d, 0xad, 0x38,
    0x18, 0x80, 0x60, 0x30, 0x4b, 0x31, 0x04, 0xd0,
    0xc8, 0x6d, 0x5a, 0xe8
  }; // padded with 1s
  huffman_result_t result;
  ck_assert(huffman_encode(buf, strlen(buf), &result));
  check_encoded_val(encoded, 20, result.value, result.length);
} END_TEST

Suite* suite() {
  Suite *s = suite_create("huffman");

  TCase *tc_decoder = tcase_create("decoder");
  tcase_add_checked_fixture(tc_decoder, setup, teardown);

  tcase_add_test(tc_decoder, test_huffman_decode_single_char);
  tcase_add_test(tc_decoder, test_huffman_decode_single_char_with_eos);
  tcase_add_test(tc_decoder, test_huffman_decode_two_chars);
  tcase_add_test(tc_decoder, test_huffman_decode_two_chars_with_eos);

  tcase_add_test(tc_decoder, test_huffman_encode_single_8bit_char);
  tcase_add_test(tc_decoder, test_huffman_encode_single_5bit_char);
  tcase_add_test(tc_decoder, test_huffman_encode_single_9bit_char);
  tcase_add_test(tc_decoder, test_huffman_encode_12bit_out);
  tcase_add_test(tc_decoder, test_huffman_encode_longer_string);
  tcase_add_test(tc_decoder, test_huffman_encode_date);

  suite_add_tcase(s, tc_decoder);

  return s;
}

int main () {
  int number_failed;
  Suite *s = suite();
  SRunner *sr = srunner_create(s);
  srunner_run_all(sr, CK_NORMAL);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
