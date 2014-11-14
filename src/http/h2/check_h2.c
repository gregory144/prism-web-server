#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <check.h>
#include <limits.h>
#include <inttypes.h>

#include <dirent.h>

#include "plugin.c"
#include "h2_error.c"
#include "h2_frame.c"

#include "../request.c"
#include "../response.c"
#include "h2.c"

#include "h2_test_cmd.h"

typedef struct {
  uint8_t * buf;
  size_t length;
} written_buf_t;

typedef struct {
  uint32_t stream_id;
  enum h2_error_code_e error_code;
  char * error_string;
} caught_error_t;

binary_buffer_t in_bb;
binary_buffer_t out_bb;
binary_buffer_t throwaway_bb;
h2_frame_parser_t parser;
h2_frame_parser_t throwaway_parser;

bool should_continue_parsing = true;
size_t num_frames_parsed = 0;
h2_frame_t * last_frames[8];

size_t num_errors = 0;
caught_error_t * caught_errors[8];

static plugin_invoker_t invoker;
static h2_t * h2;

static bool write_called;
static bool close_called;

bool h2_check_write_cb(void * data, uint8_t * buf, size_t len)
{
  UNUSED(data);

  write_called = true;
  binary_buffer_write(&out_bb, buf, len);

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

static bool parse_error_cb(void * data, uint32_t stream_id, enum h2_error_code_e error_code,
    char * format, ...)
{
  UNUSED(data);

  caught_error_t * ce = malloc(sizeof(caught_error_t));
  ce->stream_id = stream_id;
  ce->error_code = error_code;
  const size_t error_string_length = 1024;

  va_list args;

  char buf[error_string_length];
  va_start(args, format);
  vsnprintf(buf, error_string_length, format, args);
  va_end(args);
  ce->error_string = strdup(buf);

  fprintf(stdout, "Parser error: stream id: %" PRIu32 ", error code: %s (0x%x), error_string: %s\n",
      stream_id, h2_error_to_string(error_code), error_code, buf);

  if (num_errors > 7) {
    fprintf(stdout, "Too many errors!");
    abort();
  }
  caught_errors[num_errors++] = ce;

  return true;
}

static bool incoming_frame_cb(void * data, const h2_frame_t * const frame)
{
  UNUSED(data);

  if (num_frames_parsed > 7) {
    fprintf(stdout, "Too many parsed frames!");
    abort();
  }
  last_frames[num_frames_parsed++] = (h2_frame_t *) frame;

  return true;
}

void setup()
{
  invoker.plugins = NULL;
  invoker.client = NULL;

  h2 = h2_init(NULL, NULL, NULL, NULL, NULL, -1, (struct plugin_invoker_t *) &invoker,
      h2_check_write_cb, h2_check_close_cb, request_init_cb);
  if (!h2) {
    abort();
  }

  write_called = false;
  close_called = false;

  parser.log = NULL;
  parser.data = NULL;
  parser.plugin_invoker = (struct plugin_invoker_t *) &invoker;
  parser.parse_error = parse_error_cb;
  parser.incoming_frame = incoming_frame_cb;

  throwaway_parser.log = NULL;
  throwaway_parser.data = NULL;
  throwaway_parser.plugin_invoker = (struct plugin_invoker_t *) &invoker;
  throwaway_parser.parse_error = parse_error_cb;
  throwaway_parser.incoming_frame = incoming_frame_cb;

  binary_buffer_init(&in_bb, 0);
  binary_buffer_init(&out_bb, 0);
  binary_buffer_init(&throwaway_bb, 0);

  should_continue_parsing = true;
  num_frames_parsed = 0;
  for (size_t i = 0; i < 8; i++) {
    last_frames[i] = NULL;
  }

  num_errors = 0;
  for (size_t i = 0; i < 8; i++) {
    caught_errors[i] = NULL;
  }
}

void teardown()
{
  h2_free(h2);

  for (size_t i = 0; i < num_frames_parsed; i++) {
    free(last_frames[i]);
  }
  for (size_t i = 0; i < num_errors; i++) {
    free(caught_errors[i]);
  }
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

bool filter_files(const char * str)
{
  return str[0] != '.';
}

void assert_frames_equal(h2_frame_t * expected, h2_frame_t * actual)
{
  ck_assert_uint_eq(expected->type, actual->type);
  ck_assert_uint_eq(expected->length, actual->length);
  ck_assert_uint_eq(expected->flags, actual->flags);
  ck_assert_uint_eq(expected->stream_id, actual->stream_id);
}

h2_test_cmd_list_t * read_cmd(char * file)
{
  printf("file name: %s\n", file);
  FILE * fp = fopen(file, "r");
  if (!fp) {
    abort();
  }

  printf("Reading frame:\n");
  h2_test_cmd_list_t * cmd_list = h2_test_cmd_list_parse(&parser, fp);
  fclose(fp);

  ck_assert(!!cmd_list);
  return cmd_list;
}

void test_sequence_file(const char * name)
{
  size_t file_length = strlen(name) + 32;
  char in_file[file_length];
  snprintf(in_file, file_length, "./tests/%s.in", name);
  char out_file[file_length];
  snprintf(out_file, file_length, "./tests/%s.out", name);

  uint8_t buf[] = {
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
  };
  uint8_t * in = malloc(sizeof buf);
  memcpy(in, buf, sizeof buf);
  h2_read(h2, in, sizeof(buf) - 1);

  ck_assert(h2->received_connection_preface);

  size_t out_pos = 0;

  h2_test_cmd_list_t * curr = read_cmd(in_file);
  while (curr) {
    h2_frame_t * frame = curr->cmd->frame;
    switch (curr->cmd->cmd) {
      case TEST_CMD_SEND:
        {
          printf("Sending frame: %s, %u, %u\n",
            frame_type_to_string(frame->type), frame->flags, frame->stream_id);
          h2_frame_emit(&parser, &in_bb, frame);

          in = binary_buffer_start(&in_bb);
          size_t in_length = binary_buffer_size(&in_bb);
          printf("Writing frames: %zu\n", in_length);
          h2_read(h2, in, in_length);
        }
        break;
      case TEST_CMD_RECV:
        {
          ck_assert(write_called);

          h2_frame_t * expected_frame = frame;
          printf("Expecting frame: %s %u %u\n", frame_type_to_string(expected_frame->type), expected_frame->flags, expected_frame->stream_id);
          // emit the frame to measure the frame length
          h2_frame_emit(&throwaway_parser, &throwaway_bb, expected_frame);
          uint8_t * out = binary_buffer_start(&out_bb);
          size_t out_length = binary_buffer_size(&out_bb);
          printf("Out: %p\n", out);
          printf("Out buffer: %zu, %zu\n", out_length, out_pos);
          h2_frame_t * out_frame = h2_frame_parse(&parser, out, out_length, &out_pos);
          printf("Received frame: %s %u %u\n", frame_type_to_string(out_frame->type), out_frame->flags, out_frame->stream_id);
          ck_assert((out_frame && expected_frame) || (!out_frame && !expected_frame));
          if (!out_frame || !expected_frame) {
            break;
          }
          assert_frames_equal(expected_frame, out_frame);
        }
        break;
    }
    curr = curr->next;
  }
}

START_TEST(test_h2_frame_sequences)
{
  printf("Starting test\n");
  struct dirent * dir;
  DIR * d = opendir("tests");
  if (d)
  {
    while ((dir = readdir(d)) != NULL)
    {
      printf("%s\n", dir->d_name);
      if (filter_files(dir->d_name)) {
        char * seq_file = strdup(dir->d_name);
        seq_file[strlen(seq_file) - 3] = '\0';
        test_sequence_file(seq_file);
        free(seq_file);
      }
    }

    closedir(d);
  }
}
END_TEST

Suite * h2_suite()
{
  Suite * s = suite_create("h2");

  TCase * tc = tcase_create("h2");
  tcase_add_checked_fixture(tc, setup, teardown);

  tcase_add_test(tc, test_h2_valid_connection_preface);
  tcase_add_test(tc, test_h2_valid_connection_preface_in_2_packets);
  tcase_add_test(tc, test_h2_invalid_connection_preface);
  tcase_add_test(tc, test_h2_invalid_connection_preface_in_2_packets);

  tcase_add_test(tc, test_h2_frame_sequences);

  suite_add_tcase(s, tc);

  return s;
}

int main()
{
  Suite * s = h2_suite();
  SRunner * sr = srunner_create(s);
  srunner_run_all(sr, CK_NORMAL);
  int number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
