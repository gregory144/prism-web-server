#include <stdlib.h>
#include <stdio.h>
#include <check.h>

#include "../src/huffman.h"

void setup() {
}

void teardown() {
}

START_TEST(test_huffman_decode_single_char) {
  char buf[] = { 0xdf }; // 0b11011111 (65/A)
  ck_assert_str_eq("A", huffman_decode(buf, 1));
} END_TEST

START_TEST(test_huffman_decode_single_char_with_eos) {
  char buf[] = { 0x3F }; // 0b00111111 (50/2)
  ck_assert_str_eq("2", huffman_decode(buf, 1));
} END_TEST

START_TEST(test_huffman_decode_two_chars) {
  char buf[] = { 0xe1, 0xee }; // 0b1110000 111101110 (70/F, 71/G)
  ck_assert_str_eq("FG", huffman_decode(buf, 2));
} END_TEST

START_TEST(test_huffman_decode_two_chars_with_eos) {
  char buf[] = { 0x2c, 0xbf }; // 0b00101100 10111111 (48/0, 45/-)
  ck_assert_str_eq("0-", huffman_decode(buf, 2));
} END_TEST

START_TEST(test_huffman_encode_single_8bit_char) {
  // 'E' == 0xed
  char buf[] = { 'E' };
  char result[] = { 0xed, 0 };
  ck_assert_str_eq(result, huffman_encode(buf, 1));
} END_TEST

START_TEST(test_huffman_encode_single_5bit_char) {
  // 'T' == 0xe
  char buf[] = { 'T' };
  char result[] = { 0x77, 0 }; // padded with 1s
  ck_assert_str_eq(result, huffman_encode(buf, 1));
} END_TEST

START_TEST(test_huffman_encode_single_10bit_char) {
  // 'K' == 0x3f9 0b1111111001
  // 1111 1110 0111 1111
  char buf[] = { 'K' };
  char result[] = { 0xFE, 0x7F, 0 }; // padded with 1s
  ck_assert_str_eq(result, huffman_encode(buf, 1));
} END_TEST

START_TEST(test_huffman_encode_12bit_out) {
  // 'M' == 0x28 101000
  // 'G' == 0x27 100111
  // 1010 0010 0111 1111
  char buf[] = { 'M', 'G' };
  char result[] = { 0xA2, 0x7F, 0 }; // padded with 1s
  ck_assert_str_eq(result, huffman_encode(buf, 2));
} END_TEST

START_TEST(test_huffman_encode_longer_string) {
  fprintf(stderr, "HELLO WORLD------------\n");
  // 'H' == 111110000 (9) 1f0
  // 'e' == 10000 (5) 10
  // 'l' == 1110010 (7) 72
  // 'l' == 1110010 (7) 72
  // 'o' == 101111 (6) 2f
  // ' ' == 0000 (4) 0
  // 'W' == 11110011 (8) f3
  // 'o' == 101111 (6) 2f
  // 'r' == 110001 (6) 31
  // 'l' == 1110010 (7) 72
  // 'd' == 101011 (6) 2b
  // '!' == 111111111010 (12) ffa
  //
  // 1111 1000 0100 0011 1001 0111 0010 1011
  // 1100 0011 1100 1110 1111 1100 0111 1001
  // 0101 0111 1111 1111 0101 1111
  char buf[] = "Hello World!";
  char result[] = {
    0xF8, 0x43, 0x97, 0x2B,
    0xC3, 0xCE, 0xFC, 0x79,
    0x57, 0xFF, 0x5F, 0
  }; // padded with 1s
  ck_assert_str_eq(result, huffman_encode(buf, 12));
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
