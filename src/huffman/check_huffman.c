#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <check.h>

#include "huffman.c"

void check_encoded_val(unsigned char expected[], size_t expected_length, unsigned char result[], size_t length)
{
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

void setup()
{
}

void teardown()
{
}

START_TEST(test_huffman_decode_single_char)
{
  uint8_t buf[] = { 0xfc }; // 0b11111100 (88/X)
  huffman_result_t result;
  ck_assert(huffman_decode(buf, 1, &result));
  ck_assert_int_eq(1, result.length);
  ck_assert_str_eq("X", (char *)result.value);
}
END_TEST

START_TEST(test_huffman_decode_single_char_with_eos)
{
  uint8_t buf[] = { 0x83 }; // 0b10000011 (61/=)
  huffman_result_t result;
  ck_assert(huffman_decode(buf, 1, &result));
  ck_assert_int_eq(1, result.length);
  ck_assert_str_eq("=", (char *)result.value);
}
END_TEST

START_TEST(test_huffman_decode_two_chars)
{
  uint8_t buf[] = { 0xf9, 0xfa }; // 0b11111001 11111010 (42/*, 44/,)
  huffman_result_t result;
  ck_assert(huffman_decode(buf, 2, &result));
  ck_assert_int_eq(2, result.length);
  ck_assert_str_eq("*,", (char *)result.value);
}
END_TEST

START_TEST(test_huffman_decode_two_chars_with_eos)
{
  uint8_t buf[] = { 0xd3, 0xb3 }; // 0b1101001110110011 (78/N, 81/Q)
  huffman_result_t result;
  ck_assert(huffman_decode(buf, 2, &result));
  ck_assert_int_eq(2, result.length);
  ck_assert_str_eq("NQ", (char *)result.value);
}
END_TEST

START_TEST(test_huffman_encode_single_8bit_char)
{
  char buf[] = { ';' };
  uint8_t encoded[] = { 0xfb };

  huffman_result_t result;
  ck_assert(huffman_encode(buf, 1, &result));
  check_encoded_val(encoded, 1, result.value, result.length);
}
END_TEST

START_TEST(test_huffman_encode_single_5bit_char)
{
  char buf[] = { 't' };
  uint8_t encoded[] = { 0x4f }; // 01001111 padded with 1s

  huffman_result_t result;
  ck_assert(huffman_encode(buf, 1, &result));
  check_encoded_val(encoded, 1, result.value, result.length);
}
END_TEST

START_TEST(test_huffman_encode_single_10bit_char)
{
  char buf[] = { '?' };
  uint8_t encoded[] = { 0xff, 0x3f }; // padded with 1s

  huffman_result_t result;
  ck_assert(huffman_encode(buf, 1, &result));
  check_encoded_val(encoded, 2, result.value, result.length);
}
END_TEST

START_TEST(test_huffman_encode_12bit_out)
{
  char buf[] = { '5', '4' }; // 01101101 10101111
  uint8_t encoded[] = { 0x6d, 0xaf }; // padded with 1s
  huffman_result_t result;
  ck_assert(huffman_encode(buf, 2, &result));
  check_encoded_val(encoded, 2, result.value, result.length);
}
END_TEST

START_TEST(test_huffman_encode_longer_string)
{
  char buf[] = "Hello World!";
  /*'H' ( 72)  |1100011                                      63  [ 7]*/
  /*'e' (101)  |00101                                         5  [ 5]*/
  /*'l' (108)  |101000                                       28  [ 6]*/
  /*'l' (108)  |101000                                       28  [ 6]*/
  /*'o' (111)  |00111                                         7  [ 5]*/
  /*' ' ( 32)  |010100                                       14  [ 6]*/
  /*'W' ( 87)  |1110010                                      72  [ 7]*/
  /*'o' (111)  |00111                                         7  [ 5]*/
  /*'r' (114)  |101100                                       2c  [ 6]*/
  /*'l' (108)  |101000                                       28  [ 6]*/
  /*'d' (100)  |100100                                       24  [ 6]*/
  /*'!' ( 33)  |11111110|00                                 3f8  [10]*/


  uint8_t encoded[] = {
    0xC6, 0x5A, 0x28, 0x3A, 0x9C, 0x8F, 0x65, 0x12, 0x7F, 0x1F
  }; // padded with 1s
  huffman_result_t result;
  ck_assert(huffman_encode(buf, 12, &result));
  check_encoded_val(encoded, 10, result.value, result.length);
}
END_TEST

START_TEST(test_huffman_encode_date)
{

  /*'W' ( 87)  |1110010                                      72  [ 7]*/
  /*'e' (101)  |00101                                         5  [ 5]*/
  /*'d' (100)  |100100                                       24  [ 6]*/
  /*',' ( 44)  |11111010                                     fa  [ 8]*/
  /*' ' ( 32)  |010100                                       14  [ 6]*/
  /*'0' ( 48)  |00000                                         0  [ 5]*/
  /*'5' ( 53)  |011011                                       1b  [ 6]*/
  /*' ' ( 32)  |010100                                       14  [ 6]*/
  /*'M' ( 77)  |1101000                                      68  [ 7]*/
  /*'a' ( 97)  |00011                                         3  [ 5]*/
  /*'r' (114)  |101100                                       2c  [ 6]*/
  /*' ' ( 32)  |010100                                       14  [ 6]*/
  /*'2' ( 50)  |00010                                         2  [ 5]*/
  /*'0' ( 48)  |00000                                         0  [ 5]*/
  /*'1' ( 49)  |00001                                         1  [ 5]*/
  /*'4' ( 52)  |011010                                       1a  [ 6]*/
  /*' ' ( 32)  |010100                                       14  [ 6]*/
  /*'0' ( 48)  |00000                                         0  [ 5]*/
  /*'9' ( 57)  |011111                                       1f  [ 6]*/
  /*':' ( 58)  |1011100                                      5c  [ 7]*/
  /*'2' ( 50)  |00010                                         2  [ 5]*/
  /*'0' ( 48)  |00000                                         0  [ 5]*/
  /*':' ( 58)  |1011100                                      5c  [ 7]*/
  /*'5' ( 53)  |011011                                       1b  [ 6]*/
  /*'8' ( 56)  |011110                                       1e  [ 6]*/
  /*' ' ( 32)  |010100                                       14  [ 6]*/
  /*'G' ( 71)  |1100010                                      62  [ 7]*/
  /*'M' ( 77)  |1101000                                      68  [ 7]*/
  /*'T' ( 84)  |1101111                                      6f  [ 7]*/

  char buf[] = "Wed, 05 Mar 2014 09:20:58 GMT";
  uint8_t encoded[] = {
    0xE4, 0x59, 0x3E, 0x94, 0x03, 0x6A, 0x68, 0x1D,
    0x8A, 0x08, 0x01, 0x69, 0x40, 0x3F, 0x70, 0x40,
    0xB8, 0xDB, 0xCA, 0x62, 0xD1, 0xBF
  }; // padded with 1s
  huffman_result_t result;
  ck_assert(huffman_encode(buf, strlen(buf), &result));
  check_encoded_val(encoded, 22, result.value, result.length);
}
END_TEST

Suite * suite()
{
  Suite * s = suite_create("huffman");

  TCase * tc_decoder = tcase_create("decoder");
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

int main()
{
  int number_failed;
  Suite * s = suite();
  SRunner * sr = srunner_create(s);
  srunner_run_all(sr, CK_NORMAL);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
