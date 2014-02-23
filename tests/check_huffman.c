#include <stdlib.h>
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

Suite* suite() {
  Suite *s = suite_create("huffman");

  TCase *tc_decoder = tcase_create("decoder");
  tcase_add_checked_fixture(tc_decoder, setup, teardown);
  tcase_add_test(tc_decoder, test_huffman_decode_single_char);
  tcase_add_test(tc_decoder, test_huffman_decode_single_char_with_eos);
  tcase_add_test(tc_decoder, test_huffman_decode_two_chars);
  tcase_add_test(tc_decoder, test_huffman_decode_two_chars_with_eos);
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
