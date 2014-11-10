#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <check.h>
#include <limits.h>
#include <inttypes.h>

#include "plugin.c"
#include "h2_error.c"
#include "h2_frame.c"

#include "../request.c"
#include "../response.c"
#include "h2.c"

typedef struct {
  uint8_t * buf;
  size_t length;
} written_buf_t;

static plugin_invoker_t invoker;
static h2_t * h2;

static bool write_called;
static bool close_called;

bool h2_check_write_cb(void * data, uint8_t * buf, size_t len)
{
  UNUSED(data);
  UNUSED(buf);
  UNUSED(len);

  write_called = true;

  return true;
}

void h2_check_close_cb(void * data)
{
  UNUSED(data);

  close_called = true;
}

http_request_t * request_init_cb(void * data, void * user_data, header_list_t * headers)
{
  UNUSED(data);
  UNUSED(user_data);
  UNUSED(headers);

  return NULL;
}

void setup()
{
  invoker.plugins = NULL;
  invoker.client = NULL;

  h2 = h2_init(NULL, NULL, NULL, NULL, NULL, -1, (struct plugin_invoker_t *) &invoker,
      h2_check_write_cb, h2_check_close_cb, request_init_cb);
  if (!h2) {
    printf("Unable to init h2 object\n");
    abort();
  }

  write_called = false;
  close_called = false;
}

void teardown()
{
  h2_free(h2);
}

START_TEST(test_h2_valid_connection_preface)
{
  uint8_t buf[] = {
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
  };
  uint8_t * in = malloc(sizeof buf);
  memcpy(in, buf, sizeof buf);
  h2_read(h2, in, sizeof buf);

  ck_assert(!close_called);
}
END_TEST

START_TEST(test_h2_invalid_connection_preface)
{
  uint8_t buf[] = {
    "PRI * HTTP/1.1\r\n\r\nSM\r\n\r\n"
  };
  uint8_t * in = malloc(sizeof buf);
  memcpy(in, buf, sizeof buf);
  h2_read(h2, in, sizeof buf);

  ck_assert(close_called);
}
END_TEST

START_TEST(test_h2_valid_connection_preface_in_2_packets)
{
  uint8_t buf1[] = {
    "PRI * HTTP/2.0"
  };
  size_t in1_length = sizeof buf1 - 1;
  uint8_t buf2[] = {
    "\r\n\r\nSM\r\n\r\n"
  };
  size_t in2_length = sizeof buf2 - 1;
  uint8_t * in1 = malloc(in1_length);
  uint8_t * in2 = malloc(in2_length);
  memcpy(in1, buf1, in1_length);
  memcpy(in2, buf2, in2_length);
  h2_read(h2, in1, in1_length);
  h2_read(h2, in2, in2_length);

  ck_assert(!close_called);
}
END_TEST

START_TEST(test_h2_invalid_connection_preface_in_2_packets)
{
  uint8_t buf1[] = {
    "PRI * HTTP/1.1"
  };
  size_t in1_length = sizeof buf1 - 1;
  uint8_t buf2[] = {
    "\r\n\r\nSM\r\n\r\n"
  };
  size_t in2_length = sizeof buf2 - 1;
  uint8_t * in1 = malloc(in1_length);
  uint8_t * in2 = malloc(in2_length);
  memcpy(in1, buf1, in1_length);
  memcpy(in2, buf2, in2_length);
  h2_read(h2, in1, in1_length);
  h2_read(h2, in2, in2_length);

  ck_assert(close_called);
}
END_TEST

Suite * hpack_suite()
{
  Suite * s = suite_create("h2");

  TCase * tc = tcase_create("h2");
  tcase_add_checked_fixture(tc, setup, teardown);

  tcase_add_test(tc, test_h2_valid_connection_preface);
  tcase_add_test(tc, test_h2_valid_connection_preface_in_2_packets);
  tcase_add_test(tc, test_h2_invalid_connection_preface);
  tcase_add_test(tc, test_h2_invalid_connection_preface_in_2_packets);

  suite_add_tcase(s, tc);

  return s;
}

int main()
{
  Suite * s = hpack_suite();
  SRunner * sr = srunner_create(s);
  srunner_run_all(sr, CK_NORMAL);
  int number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
