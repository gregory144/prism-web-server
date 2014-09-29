#include <stdlib.h>
#include <stdio.h>
#include <check.h>

#include "binary_buffer.c"
#include "util.c"

binary_buffer_t * buffer = NULL;
uint8_t to_write[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };

void setup()
{
}

void teardown()
{
  if (buffer) {
    binary_buffer_free(buffer);
    free(buffer);
  }
}

START_TEST(test_write)
{
  buffer = binary_buffer_init(NULL, 128);
  ck_assert(buffer != NULL);
  size_t len = sizeof(to_write) / sizeof(uint8_t);
  ck_assert(binary_buffer_write(buffer, to_write, len));
  ck_assert_uint_eq(len, binary_buffer_size(buffer));
  size_t i;

  for (i = 0; i < len; i++) {
    ck_assert_uint_eq(i + 1, binary_buffer_read_index(buffer, i));
  }
}
END_TEST

START_TEST(test_write_multiple)
{
  buffer = binary_buffer_init(NULL, 128);
  ck_assert(buffer != NULL);
  size_t len = sizeof(to_write) / sizeof(uint8_t);
  ck_assert(binary_buffer_write(buffer, to_write, len));
  ck_assert(binary_buffer_write(buffer, to_write, len));
  ck_assert(binary_buffer_write(buffer, to_write, len));
  ck_assert_uint_eq(len * 3, binary_buffer_size(buffer));
  size_t write_number = 0;
  size_t i = 0;

  for (write_number = 0; write_number < 3; write_number++) {
    for (; i < len; i++) {
      ck_assert_uint_eq(i + 1, binary_buffer_read_index(buffer, i));
    }
  }
}
END_TEST

START_TEST(test_write_byte)
{
  buffer = binary_buffer_init(NULL, 128);
  ck_assert(buffer != NULL);
  uint8_t value = 100;
  ck_assert(binary_buffer_write_curr_index(buffer, value));
  ck_assert_uint_eq(1, binary_buffer_size(buffer));
  ck_assert_uint_eq(value, binary_buffer_read_index(buffer, 0));
}
END_TEST

START_TEST(test_write_bytes)
{
  buffer = binary_buffer_init(NULL, 128);
  ck_assert(buffer != NULL);
  uint8_t value1 = 10;
  uint8_t value2 = 20;
  uint8_t value3 = 30;
  ck_assert(binary_buffer_write_curr_index(buffer, value1));
  ck_assert(binary_buffer_write_curr_index(buffer, value2));
  ck_assert(binary_buffer_write_curr_index(buffer, value3));
  ck_assert_uint_eq(3, binary_buffer_size(buffer));
  ck_assert_uint_eq(value1, binary_buffer_read_index(buffer, 0));
  ck_assert_uint_eq(value2, binary_buffer_read_index(buffer, 1));
  ck_assert_uint_eq(value3, binary_buffer_read_index(buffer, 2));
}
END_TEST

START_TEST(test_grow)
{
  buffer = binary_buffer_init(NULL, 16);
  ck_assert(buffer != NULL);
  size_t len = sizeof(to_write) / sizeof(uint8_t);

  for (int i = 0; i < 100; i++) {
    ck_assert(binary_buffer_write(buffer, to_write, len));
  }

  ck_assert_uint_eq(len * 100, binary_buffer_size(buffer));
  size_t write_number = 0;
  size_t i = 0;

  for (write_number = 0; write_number < 100; write_number++) {
    for (; i < len; i++) {
      ck_assert_uint_eq(i + 1, binary_buffer_read_index(buffer, i));
    }
  }
}
END_TEST

Suite * suite()
{
  Suite * s = suite_create("binary buffer");

  TCase * tc = tcase_create("binary buffer");
  tcase_add_checked_fixture(tc, setup, teardown);

  tcase_add_test(tc, test_write);
  tcase_add_test(tc, test_write_multiple);
  tcase_add_test(tc, test_write_byte);
  tcase_add_test(tc, test_write_bytes);

  tcase_add_test(tc, test_grow);

  suite_add_tcase(s, tc);

  return s;
}

int main()
{
  Suite * s = suite();
  SRunner * sr = srunner_create(s);
  srunner_run_all(sr, CK_NORMAL);
  int number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
