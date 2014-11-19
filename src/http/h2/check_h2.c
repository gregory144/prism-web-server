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

#define MAX_TEST_FILES 1024

static size_t num_test_files;
static char * test_files[MAX_TEST_FILES];

typedef struct {
  uint8_t * buf;
  size_t length;
} written_buf_t;

typedef struct {
  uint32_t stream_id;
  enum h2_error_code_e error_code;
  char * error_string;
} caught_error_t;

binary_buffer_t * client_in_bb;
binary_buffer_t * client_out_bb;
binary_buffer_t * server_in_bb;
binary_buffer_t * server_out_bb;
binary_buffer_t * throwaway_bb;
h2_frame_parser_t server_parser;
h2_frame_parser_t client_parser;
h2_frame_parser_t throwaway_parser;

bool should_continue_parsing = true;
size_t num_frames_parsed = 0;
h2_frame_t * last_frames[8];

size_t num_errors = 0;
caught_error_t * caught_errors[8];

static plugin_list_t plugin_list;
static plugin_handlers_t plugin_handlers;
static plugin_t request_plugin;
static plugin_invoker_t invoker;
static h2_t * server_h2;

static bool write_called;
static bool close_called;

bool h2_check_write_cb(void * data, uint8_t * buf, size_t len)
{
  UNUSED(data);

  write_called = true;
  binary_buffer_write(server_out_bb, buf, len);

  return true;
}

void h2_check_close_cb(void * data)
{
  UNUSED(data);
  printf("Connection closed\n");

  close_called = true;
}

http_request_t * request_init_cb(void * data, void * user_data, header_list_t * headers)
{
  UNUSED(data);
  h2_stream_t * stream = user_data;

  return http_request_init(stream, NULL, headers);
}

struct client_t;

bool plugin_request_handler(plugin_t * plugin, struct client_t * client, http_request_t * request,
    http_response_t * response)
{
  UNUSED(plugin);
  UNUSED(client);

  h2_stream_t * stream = request->handler_data;

  if (strcmp(http_request_method(request), "POST") == 0) {
    http_response_status_set(response, 200);

    return h2_response_write(stream, response, NULL, 0, false);
  }

  char * resp_text = strdup("Don't forget to bring a towel");
  size_t content_length = strlen(resp_text);

  http_response_status_set(response, 200);

  request->handler_data = NULL;

  return h2_response_write(stream, response, (uint8_t *) resp_text, content_length, true);
}

bool plugin_data_handler(plugin_t * plugin, struct client_t * client, http_request_t * request,
                                      http_response_t * response,
                                      uint8_t * buf, size_t length, bool last, bool free_buf)
{
  UNUSED(plugin);
  UNUSED(client);

  h2_stream_t * stream = request->handler_data;
  request->handler_data = NULL;

  uint8_t * out = malloc(sizeof(uint8_t) * length);
  // convert all bytes to lowercase
  size_t i;

  for (i = 0; i < length; i++) {
    out[i] = *(buf + i);
  }

  h2_response_write_data(stream, response, out, length, last);

  if (free_buf) {
    free(buf);
  }

  return true;

}

static bool plugin_handle(plugin_t * plugin, struct client_t * client, enum plugin_callback_e cb, va_list args)
{
  switch (cb) {
    case HANDLE_REQUEST:
      {
        http_request_t * request = va_arg(args, http_request_t *);
        http_response_t * response = va_arg(args, http_response_t *);
        return plugin_request_handler(plugin, client, request, response);
      }

    case HANDLE_DATA:
      {
        http_request_t * request = va_arg(args, http_request_t *);
        http_response_t * response = va_arg(args, http_response_t *);
        uint8_t * buf = va_arg(args, uint8_t *);
        size_t length = va_arg(args, size_t);
        bool last = (bool) va_arg(args, int);
        bool free_buf = (bool) va_arg(args, int);
        return plugin_data_handler(plugin, client, request, response, buf, length, last, free_buf);
      }

    default:
      return false;
  }
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

  printf("Parser error: stream id: %" PRIu32 ", error code: %s (0x%x), error_string: %s\n",
      stream_id, h2_error_to_string(error_code), error_code, buf);

  if (num_errors > 7) {
    printf("Too many errors!");
    abort();
  }
  caught_errors[num_errors++] = ce;

  return true;
}

static bool incoming_frame_cb(void * data, const h2_frame_t * const frame)
{
  UNUSED(data);

  if (num_frames_parsed > 7) {
    printf("Too many parsed frames!");
    abort();
  }
  if (!frame) {
    abort();
  }
  last_frames[num_frames_parsed++] = (h2_frame_t *) frame;

  return true;
}

static bool throwaway_incoming_frame_cb(void * data, const h2_frame_t * const frame)
{
  UNUSED(data);
  UNUSED(frame);
  //ignore it

  return true;
}

void setup()
{
  plugin_handlers.handle = plugin_handle;
  request_plugin.handlers = &plugin_handlers;
  plugin_list.plugin = &request_plugin;
  invoker.plugins = &plugin_list;
  invoker.client = NULL;

  server_h2 = h2_init(NULL, NULL, NULL, NULL, NULL, -1, (struct plugin_invoker_t *) &invoker,
      h2_check_write_cb, h2_check_close_cb, request_init_cb);
  if (!server_h2) {
    abort();
  }

  write_called = false;
  close_called = false;

  server_parser.log = NULL;
  server_parser.data = NULL;
  server_parser.plugin_invoker = (struct plugin_invoker_t *) &invoker;
  server_parser.parse_error = parse_error_cb;
  server_parser.incoming_frame = incoming_frame_cb;

  client_parser.log = NULL;
  client_parser.data = NULL;
  client_parser.plugin_invoker = (struct plugin_invoker_t *) &invoker;
  client_parser.parse_error = parse_error_cb;
  client_parser.incoming_frame = incoming_frame_cb;

  throwaway_parser.log = NULL;
  throwaway_parser.data = NULL;
  throwaway_parser.plugin_invoker = (struct plugin_invoker_t *) &invoker;
  throwaway_parser.parse_error = parse_error_cb;
  throwaway_parser.incoming_frame = throwaway_incoming_frame_cb;

  server_in_bb = binary_buffer_init(NULL, 0);
  server_out_bb = binary_buffer_init(NULL, 0);
  client_in_bb = binary_buffer_init(NULL, 0);
  client_out_bb = binary_buffer_init(NULL, 0);
  throwaway_bb = binary_buffer_init(NULL, 0);

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
  h2_free(server_h2);
  binary_buffer_free(server_in_bb);
  free(server_in_bb);
  binary_buffer_free(server_out_bb);
  free(server_out_bb);
  binary_buffer_free(client_in_bb);
  free(client_in_bb);
  binary_buffer_free(client_out_bb);
  free(client_out_bb);
  binary_buffer_free(throwaway_bb);
  free(throwaway_bb);

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
  h2_read(server_h2, in, sizeof buf);

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
  h2_read(server_h2, in, sizeof buf);

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
  h2_read(server_h2, in1, in1_length);
  h2_read(server_h2, in2, in2_length);

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
  h2_read(server_h2, in1, in1_length);
  h2_read(server_h2, in2, in2_length);

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

  switch (expected->type) {
    case FRAME_TYPE_DATA:
      {
        h2_frame_data_t * expected_data = (h2_frame_data_t *) expected;
        h2_frame_data_t * actual_data = (h2_frame_data_t *) actual;
        ck_assert_uint_eq(expected_data->payload_length, actual_data->payload_length);
        for (size_t i = 0; i < expected_data->payload_length; i++) {
          ck_assert_uint_eq(expected_data->payload[i], actual_data->payload[i]);
        }
      }
      break;
    case FRAME_TYPE_HEADERS:
      {
        h2_frame_headers_t * expected_headers = (h2_frame_headers_t *) expected;
        h2_frame_headers_t * actual_headers = (h2_frame_headers_t *) actual;
        ck_assert_uint_eq(expected_headers->header_block_fragment_length,
            actual_headers->header_block_fragment_length);
        for (size_t i = 0; i < expected_headers->header_block_fragment_length; i++) {
          ck_assert_uint_eq(expected_headers->header_block_fragment[i],
              actual_headers->header_block_fragment[i]);
        }
      }
      break;
    case FRAME_TYPE_PRIORITY:
      {
        h2_frame_priority_t * expected_priority = (h2_frame_priority_t *) expected;
        h2_frame_priority_t * actual_priority = (h2_frame_priority_t *) actual;
        ck_assert_uint_eq(expected_priority->priority_exclusive, actual_priority->priority_exclusive);
        ck_assert_uint_eq(expected_priority->priority_stream_dependency, actual_priority->priority_stream_dependency);
        ck_assert_uint_eq(expected_priority->priority_weight, actual_priority->priority_weight);
      }
      break;
    case FRAME_TYPE_SETTINGS:
      {
        h2_frame_settings_t * expected_settings = (h2_frame_settings_t *) expected;
        h2_frame_settings_t * actual_settings = (h2_frame_settings_t *) actual;
        ck_assert_uint_eq(expected_settings->num_settings, actual_settings->num_settings);
        for (size_t i = 0; i < expected_settings->num_settings; i++) {
          ck_assert_uint_eq(expected_settings->settings[i].id, actual_settings->settings[i].id);
          ck_assert_uint_eq(expected_settings->settings[i].value, actual_settings->settings[i].value);
        }
      }
      break;
    case FRAME_TYPE_RST_STREAM:
      {
        h2_frame_rst_stream_t * expected_rst_stream = (h2_frame_rst_stream_t *) expected;
        h2_frame_rst_stream_t * actual_rst_stream = (h2_frame_rst_stream_t *) actual;
        ck_assert_uint_eq(expected_rst_stream->error_code, actual_rst_stream->error_code);
      }
      break;
    case FRAME_TYPE_PUSH_PROMISE:
      {
        h2_frame_push_promise_t * expected_push_promise = (h2_frame_push_promise_t *) expected;
        h2_frame_push_promise_t * actual_push_promise = (h2_frame_push_promise_t *) actual;
        ck_assert_uint_eq(expected_push_promise->padding_length, actual_push_promise->padding_length);
        ck_assert_uint_eq(expected_push_promise->promised_stream_id, actual_push_promise->promised_stream_id);
        ck_assert_uint_eq(expected_push_promise->header_block_fragment_length,
            actual_push_promise->header_block_fragment_length);
        for (size_t i = 0; i < expected_push_promise->header_block_fragment_length; i++) {
          ck_assert_uint_eq(expected_push_promise->header_block_fragment[i],
              actual_push_promise->header_block_fragment[i]);
        }
      }
      break;
    case FRAME_TYPE_PING:
      {
        h2_frame_ping_t * expected_ping = (h2_frame_ping_t *) expected;
        h2_frame_ping_t * actual_ping = (h2_frame_ping_t *) actual;
        for (size_t i = 0; i < PING_OPAQUE_DATA_LENGTH; i++) {
          ck_assert_uint_eq(expected_ping->opaque_data[i], actual_ping->opaque_data[i]);
        }
      }
      break;
    case FRAME_TYPE_GOAWAY:
      {
        h2_frame_goaway_t * expected_goaway = (h2_frame_goaway_t *) expected;
        h2_frame_goaway_t * actual_goaway = (h2_frame_goaway_t *) actual;
        ck_assert_uint_eq(expected_goaway->last_stream_id, actual_goaway->last_stream_id);
        ck_assert_uint_eq(expected_goaway->error_code, actual_goaway->error_code);
        ck_assert_uint_eq(expected_goaway->debug_data_length, actual_goaway->debug_data_length);
        for (size_t i = 0; i < expected_goaway->debug_data_length; i++) {
          ck_assert_uint_eq(expected_goaway->debug_data[i], actual_goaway->debug_data[i]);
        }
      }
      break;
    case FRAME_TYPE_WINDOW_UPDATE:
      {
        h2_frame_window_update_t * expected_window_update = (h2_frame_window_update_t *) expected;
        h2_frame_window_update_t * actual_window_update = (h2_frame_window_update_t *) actual;
        ck_assert_uint_eq(expected_window_update->increment, actual_window_update->increment);
      }
      break;

    case FRAME_TYPE_CONTINUATION:
      {
        h2_frame_continuation_t * expected_continuation = (h2_frame_continuation_t *) expected;
        h2_frame_continuation_t * actual_continuation = (h2_frame_continuation_t *) actual;
        ck_assert_uint_eq(expected_continuation->header_block_fragment_length,
            actual_continuation->header_block_fragment_length);
        for (size_t i = 0; i < expected_continuation->header_block_fragment_length; i++) {
          ck_assert_uint_eq(expected_continuation->header_block_fragment[i],
              actual_continuation->header_block_fragment[i]);
        }
      }
      break;
  }
}

h2_test_cmd_list_t * read_cmd(char * file)
{
  printf("%-30s %s\n", "Starting test...", file);
  FILE * fp = fopen(file, "r");
  if (!fp) {
    abort();
  }

  h2_test_cmd_list_t * cmd_list = h2_test_cmd_list_parse(fp);
  fclose(fp);

  ck_assert(!!cmd_list);
  return cmd_list;
}

void test_sequence_file(const char * file_name)
{
  size_t file_length = strlen(file_name) + 32;
  char in_file[file_length];
  snprintf(in_file, file_length, "./tests/%s", file_name);

  uint8_t preface[] = {
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
  };
  uint8_t * client_buf = malloc(sizeof preface);
  memcpy(client_buf, preface, sizeof preface);
  h2_read(server_h2, client_buf, sizeof(preface) - 1);

  ck_assert(server_h2->received_connection_preface);

  size_t server_out_pos = 0;

  h2_test_cmd_list_t * curr = read_cmd(in_file);

  while (curr) {
    switch (curr->cmd->cmd) {
      case TEST_CMD_SEND:
        {
          h2_frame_t * frame = curr->cmd->frame;
          h2_frame_emit(&client_parser, client_out_bb, frame);

          client_buf = binary_buffer_start(client_out_bb);
          size_t client_buf_length = binary_buffer_size(client_out_bb);
          uint8_t * client_buf_copy = malloc(client_buf_length);
          memcpy(client_buf_copy, client_buf, client_buf_length);
          printf("Writing frame: %s: %zu octets\n", frame_type_to_string(frame->type), client_buf_length);
          h2_read(server_h2, client_buf_copy, client_buf_length);
          binary_buffer_reset(client_out_bb, 0);
        }
        break;
      case TEST_CMD_RECV:
        {
          ck_assert(write_called);

          h2_frame_t * expected_frame = curr->cmd->frame;
          printf("Expecting frame: %s %u %u length: %u\n",
              frame_type_to_string(expected_frame->type), expected_frame->flags, expected_frame->stream_id,
              expected_frame->length);
          // emit the frame to measure the frame length
          h2_frame_emit(&throwaway_parser, throwaway_bb, expected_frame);

          uint8_t * server_out_buf = binary_buffer_start(server_out_bb);
          size_t server_out_length = binary_buffer_size(server_out_bb);
          h2_frame_t * server_out_frame = h2_frame_parse(&client_parser,
              server_out_buf, server_out_length, &server_out_pos);

          ck_assert(!!server_out_frame);
          printf("Received frame: %s %u %u\n", frame_type_to_string(server_out_frame->type),
              server_out_frame->flags, server_out_frame->stream_id);
          if (server_out_frame->type == FRAME_TYPE_GOAWAY) {
            h2_frame_goaway_t * goaway_frame = (h2_frame_goaway_t *) server_out_frame;
            printf("GOAWAY: %s\n", goaway_frame->debug_data);
          }
          ck_assert((server_out_frame && expected_frame) || (!server_out_frame && !expected_frame));
          if (!server_out_frame || !expected_frame) {
            break;
          }

          assert_frames_equal(expected_frame, server_out_frame);
        }
        break;
    }
    h2_test_cmd_list_t * prev = curr;
    curr = curr->next;
    free(prev->cmd->frame);
    free(prev->cmd);
    free(prev);
  }
}

void find_test_files()
{
  struct dirent * dir;
  DIR * d = opendir("tests");
  if (d)
  {
    while ((dir = readdir(d)) != NULL)
    {
      if (filter_files(dir->d_name)) {
        char * seq_file = strdup(dir->d_name);

        test_files[num_test_files++] = seq_file;
      }
    }

    closedir(d);
  }
}

START_TEST(test_h2_frame_sequences)
{
  test_sequence_file(test_files[_i]);
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

  find_test_files();
  tcase_add_loop_test(tc, test_h2_frame_sequences, 0, num_test_files);

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
