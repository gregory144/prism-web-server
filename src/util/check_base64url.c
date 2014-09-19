#include <stdlib.h>
#include <check.h>

#include "base64url.c"

void setup()
{
}

void teardown()
{
}

START_TEST(test_decode_output_20_bytes)
{
  binary_buffer_t buf;
  binary_buffer_init(&buf, 0);
  base64url_decode(&buf, "YW55IGNhcm5hbCBwbGVhc3VyZS4");
  char * expected = "any carnal pleasure.";
  ck_assert_int_eq(strlen(expected), binary_buffer_size(&buf));
  ck_assert_str_eq(expected, (char *) binary_buffer_start(&buf));
}
END_TEST

START_TEST(test_decode_output_19_bytes)
{
  binary_buffer_t buf;
  binary_buffer_init(&buf, 0);
  base64url_decode(&buf, "YW55IGNhcm5hbCBwbGVhc3VyZQ");
  char * expected = "any carnal pleasure";
  ck_assert_int_eq(strlen(expected), binary_buffer_size(&buf));
  ck_assert_str_eq(expected, (char *) binary_buffer_start(&buf));
}
END_TEST

START_TEST(test_decode_output_18_bytes)
{
  binary_buffer_t buf;
  binary_buffer_init(&buf, 0);
  base64url_decode(&buf, "YW55IGNhcm5hbCBwbGVhc3Vy");
  char * expected = "any carnal pleasur";
  ck_assert_int_eq(strlen(expected), binary_buffer_size(&buf));
  ck_assert_str_eq(expected, (char *) binary_buffer_start(&buf));
}
END_TEST

START_TEST(test_decode_output_17_bytes)
{
  binary_buffer_t buf;
  binary_buffer_init(&buf, 0);
  base64url_decode(&buf, "YW55IGNhcm5hbCBwbGVhc3U");
  char * expected = "any carnal pleasu";
  ck_assert_int_eq(strlen(expected), binary_buffer_size(&buf));
  ck_assert_str_eq(expected, (char *) binary_buffer_start(&buf));
}
END_TEST

START_TEST(test_decode_output_16_bytes)
{
  binary_buffer_t buf;
  binary_buffer_init(&buf, 0);
  base64url_decode(&buf, "YW55IGNhcm5hbCBwbGVhcw");
  char * expected = "any carnal pleas";
  ck_assert_int_eq(strlen(expected), binary_buffer_size(&buf));
  ck_assert_str_eq(expected, (char *) binary_buffer_start(&buf));
}
END_TEST

// AAMAAABkAAQAAP__
// 0, 0, 12, 0, 0, 0, 1, 36,
// \0 00000000
// 00000011 = 3
// 00000000
// 00000000
// 00000000
// 01100100 = 100
//
// 2 bytes id
// 4 bytes value
// id: 0x03, value: 100 (6)
// 0, 0, 16, 0, 0, 15, 63, 63
// 00000000
// 00000100 = 4
// 00000000
// 00000000
// 11111111
// 11111111 = 65535
// id: 0x04, value: 65535 (6)
//
START_TEST(test_decode_settings)
{
  binary_buffer_t buf;
  binary_buffer_init(&buf, 0);
  base64url_decode(&buf, "AAMAAABkAAQAAP__");
  char * expected = "\x00\x03\x00\x00\x00\x64\x00\x04\x00\x00\xFF\xFF";
  ck_assert_int_eq(12, binary_buffer_size(&buf));
  ck_assert_str_eq(expected, (char *) binary_buffer_start(&buf));
}
END_TEST

Suite * suite()
{
  Suite * s = suite_create("base64url");

  TCase * tc_decoder = tcase_create("decoder");
  tcase_add_checked_fixture(tc_decoder, setup, teardown);
  tcase_add_test(tc_decoder, test_decode_output_20_bytes);
  tcase_add_test(tc_decoder, test_decode_output_19_bytes);
  tcase_add_test(tc_decoder, test_decode_output_18_bytes);
  tcase_add_test(tc_decoder, test_decode_output_17_bytes);
  tcase_add_test(tc_decoder, test_decode_output_16_bytes);
  tcase_add_test(tc_decoder, test_decode_settings);
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
