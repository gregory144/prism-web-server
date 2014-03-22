#include <stdlib.h>
#include <stdio.h>
#include <check.h>

#include "../src/huffman.c"
#include "../src/util.c"

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
  uint8_t buf[] = { 0xdf }; // 0b11011111 (65/A)
  huffman_result_t* result = huffman_decode(buf, 1);
  ck_assert_int_eq(1, result->length);
  ck_assert_str_eq("A", result->value);
} END_TEST

START_TEST(test_huffman_decode_single_char_with_eos) {
  uint8_t buf[] = { 0x3F }; // 0b00111111 (50/2)
  huffman_result_t* result = huffman_decode(buf, 1);
  ck_assert_int_eq(1, result->length);
  ck_assert_str_eq("2", result->value);
} END_TEST

START_TEST(test_huffman_decode_two_chars) {
  uint8_t buf[] = { 0xe1, 0xee }; // 0b1110000 111101110 (70/F, 71/G)
  huffman_result_t* result = huffman_decode(buf, 2);
  ck_assert_int_eq(2, result->length);
  ck_assert_str_eq("FG", result->value);
} END_TEST

START_TEST(test_huffman_decode_two_chars_with_eos) {
  uint8_t buf[] = { 0x2c, 0xbf }; // 0b00101100 10111111 (48/0, 45/-)
  huffman_result_t* result = huffman_decode(buf, 2);
  ck_assert_int_eq(2, result->length);
  ck_assert_str_eq("0-", result->value);
} END_TEST

START_TEST(test_huffman_encode_single_8bit_char) {
  // 'E' == 0xee
  uint8_t buf[] = { 'E' };
  uint8_t encoded[] = { 0xee };

  huffman_result_t* result = huffman_encode(buf, 1);
  check_encoded_val(encoded, 1, result->value, result->length);
} END_TEST

START_TEST(test_huffman_encode_single_5bit_char) {
  // 'p' == 0xe
  uint8_t buf[] = { 'p' };
  uint8_t encoded[] = { 0x77 }; // padded with 1s

  huffman_result_t* result = huffman_encode(buf, 1);
  check_encoded_val(encoded, 1, result->value, result->length);
} END_TEST

START_TEST(test_huffman_encode_single_10bit_char) {
  // 'Z' == 0x3fc 0b1111111100
  // 1111 1111 0011 1111
  uint8_t buf[] = { 'Z' };
  uint8_t encoded[] = { 0xFF, 0x3F }; // padded with 1s

  huffman_result_t* result = huffman_encode(buf, 1);
  check_encoded_val(encoded, 2, result->value, result->length);
} END_TEST

START_TEST(test_huffman_encode_12bit_out) {
  // '5' == 0x28 101000
  // '4' == 0x27 100111
  // 1010 0010 0111 1111
  uint8_t buf[] = { '5', '4' };
  uint8_t encoded[] = { 0xA2, 0x7F }; // padded with 1s
  huffman_result_t* result = huffman_encode(buf, 2);
  check_encoded_val(encoded, 2, result->value, result->length);
} END_TEST

START_TEST(test_huffman_encode_longer_string) {
  // 'H' == 111101111 (9) 1ef
  // 'e' == 0001 (4) 1
  // 'l' == 01011 (5) b
  // 'l' == 01011 (5) b
  // 'o' == 01101 (5) d
  // ' ' == 11101000 (8) e8
  // 'W' == 111111010 (9) 1fa
  // 'o' == 01101 (5) d
  // 'r' == 01111 (5) f
  // 'l' == 01011 (5) b
  // 'd' == 110000 (6) 30
  // '!' == 111111111100 (12) ffc
  //
  // 1111 0111 1000 1010 1101 0110
  // 1101 1110 1000 1111 1101 0011
  // 0101 1110 1011 1100 0011 1111
  // 1111 0011
  char buf[] = "Hello World!";
  uint8_t encoded[] = {
    0xf7, 0x8a, 0xd6, 0xde,
    0x8f, 0xd3, 0x5e, 0xbc,
    0x3f, 0xf3
  }; // padded with 1s
  huffman_result_t* result = huffman_encode((uint8_t*)buf, 12);
  check_encoded_val(encoded, 10, result->value, result->length);
} END_TEST

START_TEST(test_huffman_encode_date) {
  char buf[] = "Wed, 05 Mar 2014 09:20:58 GMT";
  uint8_t encoded[] = {
    0xfd, 0x0e, 0x1d, 0x3d,
    0x05, 0xa3, 0xa3, 0xbd,
    0x0f, 0xe8, 0x39, 0x4d,
    0x3f, 0x41, 0x6c, 0xf6,
    0x1c, 0xbe, 0xca, 0x2b,
    0xe8, 0xf7, 0x77, 0xf8,
    0xff,
  }; // padded with 1s
  huffman_result_t* result = huffman_encode((uint8_t*)buf, strlen(buf));
  check_encoded_val(encoded, 25, result->value, result->length);
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
  tcase_add_test(tc_decoder, test_huffman_encode_single_10bit_char);
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
