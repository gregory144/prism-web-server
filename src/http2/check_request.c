#include <stdlib.h>
#include <stdio.h>
#include <check.h>

#include "../util/util.c"
#include "../util/multimap.c"

#include "request.c"

void setup() {
}

void teardown() {
}

#define DECODE_TEST(name, encoded_s, decoded_s) \
  START_TEST(name) { \
    char* encoded = encoded_s; \
    char* decoded = url_decode(encoded, strlen(encoded)); \
    ck_assert_str_eq(decoded, decoded_s); \
  } END_TEST

DECODE_TEST(test_request_decode_url_empty, "", "")
DECODE_TEST(test_request_decode_url_single_char, "a", "a")
DECODE_TEST(test_request_decode_url_simple, "abc", "abc")
DECODE_TEST(test_request_decode_url_space, "+", " ")
DECODE_TEST(test_request_decode_url_with_space, "abc+123", "abc 123")
DECODE_TEST(test_request_decode_url_with_many_spaces, "a+b+c++1+2+3", "a b c  1 2 3")
DECODE_TEST(test_request_decode_url_with_percent_encoding, "a%26b", "a&b")
DECODE_TEST(test_request_decode_url_percent_encoding_first, "%01", "\x01")
DECODE_TEST(test_request_decode_url_percent_encoding_last, "%FF", "\xFF")
DECODE_TEST(test_request_decode_url_with_many_percent_encodings, "a%26b%26c", "a&b&c")
DECODE_TEST(test_request_decode_url_with_consecutive_percent_encodings, "%7E%26%20", "~& ")
DECODE_TEST(test_request_decode_url_with_invalid_percent_encoding, "abc%2", "abc%2")

Suite * request_suite() {
  Suite *s = suite_create("request");

  TCase *tc_decoder = tcase_create("url_decoder");
  tcase_add_checked_fixture(tc_decoder, setup, teardown);

  tcase_add_test(tc_decoder, test_request_decode_url_empty);
  tcase_add_test(tc_decoder, test_request_decode_url_single_char);
  tcase_add_test(tc_decoder, test_request_decode_url_simple);
  tcase_add_test(tc_decoder, test_request_decode_url_space);
  tcase_add_test(tc_decoder, test_request_decode_url_with_space);
  tcase_add_test(tc_decoder, test_request_decode_url_with_many_spaces);
  tcase_add_test(tc_decoder, test_request_decode_url_with_percent_encoding);
  tcase_add_test(tc_decoder, test_request_decode_url_percent_encoding_first);
  tcase_add_test(tc_decoder, test_request_decode_url_percent_encoding_last);
  tcase_add_test(tc_decoder, test_request_decode_url_with_many_percent_encodings);
  tcase_add_test(tc_decoder, test_request_decode_url_with_consecutive_percent_encodings);
  tcase_add_test(tc_decoder, test_request_decode_url_with_invalid_percent_encoding);

  suite_add_tcase(s, tc_decoder);

  return s;
}

int main () {
  int number_failed;
  Suite *s = request_suite();
  SRunner *sr = srunner_create(s);
  srunner_run_all(sr, CK_NORMAL);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
