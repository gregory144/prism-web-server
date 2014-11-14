#ifndef H2_FRAME_LIST_H
#define H2_FRAME_LIST_H

#include <stdbool.h>

#include "h2_frame.h"

enum h2_test_cmd_e {

  TEST_CMD_SEND,
  TEST_CMD_RECV,

};

typedef struct {

  enum h2_test_cmd_e cmd;

  h2_frame_t * frame;

} h2_test_cmd_t;

typedef struct h2_test_cmd_list_s {

  h2_test_cmd_t * cmd;

  struct h2_test_cmd_list_s * next;

} h2_test_cmd_list_t;

h2_test_cmd_list_t * h2_test_cmd_list_parse(h2_frame_parser_t * frame_parser, FILE * fp);

h2_test_cmd_list_t * h2_test_cmd_list_append(h2_test_cmd_list_t * frame_list, h2_test_cmd_t * cmd);

#endif
