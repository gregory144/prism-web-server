#ifndef H2_FRAME_LIST_H
#define H2_FRAME_LIST_H

#include <stdbool.h>

#include "h2.h"

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

typedef struct {

  h2_test_cmd_list_t * list;

  hpack_context_t * sending_context;
  hpack_context_t * receiving_context;

} h2_test_cmd_context_t;

h2_test_cmd_list_t * h2_test_cmd_list_parse(FILE * fp);

h2_test_cmd_list_t * h2_test_cmd_list_append(h2_test_cmd_list_t * frame_list, h2_test_cmd_t * cmd);

#endif
