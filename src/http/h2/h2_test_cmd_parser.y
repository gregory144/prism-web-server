%{
#include <stdlib.h>

#include "util.h"
#include "h2_test_cmd.h"

#ifndef YY_TYPEDEF_YY_SCANNER_T
#define YY_TYPEDEF_YY_SCANNER_T
typedef void * yyscan_t;
#endif

int yylex();
int yyget_lineno(yyscan_t scanner);

int yyerror(h2_test_cmd_context_t * ctx, yyscan_t scanner, const char * msg) {
  UNUSED(ctx);
  UNUSED(scanner);
  printf("Error parsing frame list: %s (line %u)\n", msg, yyget_lineno(scanner));

  return 1;
}

%}

%code requires {

#ifndef YY_TYPEDEF_YY_SCANNER_T
#define YY_TYPEDEF_YY_SCANNER_T
typedef void* yyscan_t;
#endif

#include <string.h>

#include "h2.h"
#include "h2_test_cmd.h"

typedef struct settings_list_s {

  struct settings_list_s * next;

  h2_setting_t setting;

} settings_list_t;

typedef struct {

  uint8_t flags;
  uint32_t stream_number;

} frame_options_t;

typedef struct {

  bool is_default;
  bool priority_exclusive;
  uint32_t priority_stream_dependency;
  uint8_t priority_weight;

} frame_priority_t;

#define apply_padding(frame, length) \
  if ((length) > 0) { \
    (frame)->padding_length = (length) - 1; \
    (frame)->flags |= FLAG_PADDED; \
  }

#define apply_priority(frame, p) \
  (frame)->priority_exclusive = (p)->priority_exclusive; \
  (frame)->priority_stream_dependency = (p)->priority_stream_dependency; \
  (frame)->priority_weight = (p)->priority_weight; \
  if (!(p)->is_default) { \
    (frame)->flags |= FLAG_PRIORITY; \
  }

#define apply_headers(frame, context, headers) \
    header_list_t * curr = headers; \
    binary_buffer_t encoded; \
    if (!hpack_encode((context), curr, &encoded)) { \
      printf("Error encoding headers"); \
      abort(); \
    } \
    uint8_t * hpack_buf = encoded.buf; \
    size_t headers_length = binary_buffer_size(&encoded); \
    if (headers_length > DEFAULT_MAX_FRAME_SIZE) { \
      printf("Too many headers for one frame"); \
      abort(); \
    } \
    frame->header_block_fragment = malloc(headers_length); \
    memcpy(frame->header_block_fragment, hpack_buf, headers_length); \
    frame->header_block_fragment_length = headers_length; \
    header_list_free(curr); \
    binary_buffer_free(&encoded);

}

%define api.pure
%define parse.error verbose
%define parse.lac full
%lex-param   { yyscan_t scanner }
%parse-param { h2_test_cmd_context_t * ctx }
%parse-param { yyscan_t scanner }

%union {
  uint8_t frame_flag_bt;
  enum frame_type_e frame_type_bt;
  uint32_t value_bt;
  char * string_bt;
  h2_test_cmd_list_t * cmd_list_bt;
  h2_frame_t * frame_bt;
  h2_test_cmd_t * cmd_bt;
  settings_list_t * settings_list_bt;
  uint16_t setting_id_bt;
  header_list_t * header_list_bt;
  h2_test_cmd_context_t * context_bt;
  frame_options_t * frame_options_bt;
  frame_priority_t * frame_priority_bt;
}

%token TOKEN_COMMA
%token TOKEN_COLON
%token TOKEN_DOT
%token TOKEN_LPAREN
%token TOKEN_RPAREN

%token TOKEN_NEWLINE
%token TOKEN_SEND
%token TOKEN_RECV

%token TOKEN_DATA
%token TOKEN_HEADERS
%token TOKEN_PRIORITY
%token TOKEN_RST_STREAM
%token TOKEN_SETTINGS
%token TOKEN_PUSH_PROMISE
%token TOKEN_PING
%token TOKEN_GOAWAY
%token TOKEN_WINDOW_UPDATE
%token TOKEN_CONTINUATION

%token TOKEN_EXCLUSIVE
%token TOKEN_STREAM_DEPENDENCY
%token TOKEN_WEIGHT
%token TOKEN_PROMISED_STREAM_ID
%token TOKEN_PADDING
%token TOKEN_LAST_STREAM_ID
%token TOKEN_ERROR_CODE
%token TOKEN_ADDITIONAL_DATA
%token TOKEN_INCREMENT

%token <setting_id_bt> TOKEN_SETTING_ID
%token <value_bt> TOKEN_NUMBER
%token <value_bt> TOKEN_STREAM_NUMBER
%token <value_bt> TOKEN_ERROR_CODE_VALUE
%token <frame_type_bt> TOKEN_FRAME_TYPE
%token <frame_flag_bt> TOKEN_FRAME_FLAG
%token <string_bt> TOKEN_STRING

%type <context_bt> wrapper
%type <cmd_list_bt> command_list
%type <cmd_bt> command
%type <frame_bt> sent_frame
%type <frame_bt> received_frame
%type <frame_bt> data_frame
%type <frame_bt> sent_headers_frame
%type <frame_bt> received_headers_frame
%type <frame_bt> priority_frame
%type <frame_bt> rst_stream_frame
%type <frame_bt> settings_frame
%type <frame_bt> sent_push_promise_frame
%type <frame_bt> received_push_promise_frame
%type <frame_bt> ping_frame
%type <frame_bt> goaway_frame
%type <frame_bt> window_update_frame
%type <frame_bt> sent_continuation_frame
%type <frame_bt> received_continuation_frame
%type <frame_options_bt> frame_options
%type <frame_priority_bt> frame_priority
%type <settings_list_bt> settings_list
%type <header_list_bt> header_list
%type <frame_flag_bt> frame_flags
%type <value_bt> frame_stream_number
%type <value_bt> frame_padding
%type <value_bt> priority_exclusive
%type <value_bt> priority_stream_dependency
%type <value_bt> priority_weight

%%

wrapper
  : command_list {
    $$ = ctx;
    ctx->list = $1;
  }
  ;

command_list
  : {
    $$ = NULL;
  }
  | command_list command {
    $$ = h2_test_cmd_list_append($1, $2);
  }
  ;

command
  : TOKEN_SEND sent_frame {
    $$ = malloc(sizeof(h2_test_cmd_t));
    $$->cmd = TEST_CMD_SEND;
    $$->frame = $2;
  }
  | TOKEN_RECV received_frame {
    $$ = malloc(sizeof(h2_test_cmd_t));
    $$->cmd = TEST_CMD_RECV;
    $$->frame = $2;
  }
  ;

sent_frame
  : data_frame { $$ = $1; }
  | sent_headers_frame { $$ = $1; }
  | priority_frame { $$ = $1; }
  | rst_stream_frame { $$ = $1; }
  | settings_frame { $$ = $1; }
  | sent_push_promise_frame { $$ = $1; }
  | ping_frame { $$ = $1; }
  | goaway_frame { $$ = $1; }
  | window_update_frame { $$ = $1; }
  | sent_continuation_frame { $$ = $1; }
  ;

received_frame
  : data_frame { $$ = $1; }
  | received_headers_frame { $$ = $1; }
  | priority_frame { $$ = $1; }
  | rst_stream_frame { $$ = $1; }
  | settings_frame { $$ = $1; }
  | received_push_promise_frame { $$ = $1; }
  | ping_frame { $$ = $1; }
  | goaway_frame { $$ = $1; }
  | window_update_frame { $$ = $1; }
  | received_continuation_frame { $$ = $1; }
  ;

data_frame
  : TOKEN_DATA frame_options frame_padding TOKEN_STRING {
    h2_frame_data_t * frame = (h2_frame_data_t *) h2_frame_init(
      FRAME_TYPE_DATA, $2->flags, $2->stream_number);
    free($2);
    apply_padding(frame, $3);
    char * body = $4;

    frame->payload = (uint8_t *) body;
    frame->payload_length = strlen(body);

    $$ = (h2_frame_t *) frame;
  }

sent_headers_frame
  : TOKEN_HEADERS frame_options frame_padding frame_priority header_list {
    h2_frame_headers_t * frame = (h2_frame_headers_t *) h2_frame_init(
      FRAME_TYPE_HEADERS, $2->flags, $2->stream_number);
    free($2);
    apply_padding(frame, $3);
    apply_priority(frame, $4);
    free($4);
    apply_headers(frame, ctx->sending_context, $5);

    $$ = (h2_frame_t *) frame;
  }

received_headers_frame
  : TOKEN_HEADERS frame_options frame_padding frame_priority header_list {
    h2_frame_headers_t * frame = (h2_frame_headers_t *) h2_frame_init(
      FRAME_TYPE_HEADERS, $2->flags, $2->stream_number);
    free($2);
    apply_padding(frame, $3);
    apply_priority(frame, $4);
    free($4);
    apply_headers(frame, ctx->receiving_context, $5);

    $$ = (h2_frame_t *) frame;
  }

priority_frame
  : TOKEN_PRIORITY frame_options
  TOKEN_EXCLUSIVE TOKEN_COLON TOKEN_NUMBER
  TOKEN_STREAM_DEPENDENCY TOKEN_COLON TOKEN_NUMBER
  TOKEN_WEIGHT TOKEN_COLON TOKEN_NUMBER {
    h2_frame_priority_t * frame = (h2_frame_priority_t *) h2_frame_init(
      FRAME_TYPE_PRIORITY, $2->flags, $2->stream_number);
    free($2);
    frame->priority_exclusive = $5;
    frame->priority_stream_dependency = $8;
    frame->priority_weight = $11;
    $$ = (h2_frame_t *) frame;
  }
  ;

rst_stream_frame
  : TOKEN_RST_STREAM frame_options TOKEN_ERROR_CODE TOKEN_COLON TOKEN_ERROR_CODE_VALUE {
    h2_frame_rst_stream_t * frame = (h2_frame_rst_stream_t *) h2_frame_init(
      FRAME_TYPE_RST_STREAM, $2->flags, $2->stream_number);
    free($2);
    frame->error_code = $5;
    $$ = (h2_frame_t *) frame;
  }
  ;

settings_frame
  : TOKEN_SETTINGS frame_options settings_list {
    h2_frame_settings_t * frame = (h2_frame_settings_t *) h2_frame_init(
      FRAME_TYPE_SETTINGS, $2->flags, $2->stream_number);
    free($2);
    settings_list_t * curr = $3;
    frame->num_settings = 0;
    while (curr) {
      h2_setting_t * s = &frame->settings[frame->num_settings++];
      if (frame->num_settings > 6) {
        printf("Parsed too many settings\n");
        abort();
      }
      s->id = curr->setting.id;
      s->value = curr->setting.value;

      if (s->id == SETTINGS_HEADER_TABLE_SIZE) {
        hpack_header_table_adjust_size(ctx->sending_context, s->value);
      }

      settings_list_t * prev = curr;
      curr = curr->next;
      free(prev);
    }
    $$ = (h2_frame_t *) frame;
  }
  ;

sent_push_promise_frame
  : TOKEN_PUSH_PROMISE frame_options frame_padding
  TOKEN_PROMISED_STREAM_ID TOKEN_COLON TOKEN_STREAM_NUMBER
  header_list {
    h2_frame_push_promise_t * frame = (h2_frame_push_promise_t *) h2_frame_init(
      FRAME_TYPE_PUSH_PROMISE, $2->flags, $2->stream_number);
    free($2);

    apply_padding(frame, $3);
    frame->promised_stream_id = $6;
    apply_headers(frame, ctx->sending_context, $7);

    $$ = (h2_frame_t *) frame;
  }
  ;

received_push_promise_frame
  : TOKEN_PUSH_PROMISE frame_options frame_padding
  TOKEN_PROMISED_STREAM_ID TOKEN_COLON TOKEN_STREAM_NUMBER
  header_list {
    h2_frame_push_promise_t * frame = (h2_frame_push_promise_t *) h2_frame_init(
      FRAME_TYPE_PUSH_PROMISE, $2->flags, $2->stream_number);
    free($2);

    apply_padding(frame, $3);
    frame->promised_stream_id = $6;

    apply_headers(frame, ctx->receiving_context, $7);

    $$ = (h2_frame_t *) frame;
  }
  ;


ping_frame
  : TOKEN_PING frame_options TOKEN_NUMBER TOKEN_NUMBER {
    h2_frame_ping_t * frame = (h2_frame_ping_t *) h2_frame_init(
      FRAME_TYPE_PING, $2->flags, $2->stream_number);
    free($2);
    printf("PINGING: %u %u\n", $3, $4);

    frame->opaque_data[0] = ($3 >> 24) & 0xff;
    frame->opaque_data[1] = ($3 >> 16) & 0xff;
    frame->opaque_data[2] = ($3 >> 8) & 0xff;
    frame->opaque_data[3] = ($3 >> 0) & 0xff;
    frame->opaque_data[4] = ($4 >> 24) & 0xff;
    frame->opaque_data[5] = ($4 >> 16) & 0xff;
    frame->opaque_data[6] = ($4 >> 8) & 0xff;
    frame->opaque_data[7] = ($4 >> 0) & 0xff;

    $$ = (h2_frame_t *) frame;
  }
  ;

goaway_frame
  : TOKEN_GOAWAY frame_options
  TOKEN_LAST_STREAM_ID TOKEN_COLON TOKEN_STREAM_NUMBER
  TOKEN_ERROR_CODE TOKEN_COLON TOKEN_ERROR_CODE_VALUE
  TOKEN_ADDITIONAL_DATA TOKEN_COLON TOKEN_STRING {
    h2_frame_goaway_t * frame = (h2_frame_goaway_t *) h2_frame_init(
      FRAME_TYPE_GOAWAY, $2->flags, $2->stream_number);
    free($2);
    frame->last_stream_id = $5;
    frame->error_code = $8;
    frame->debug_data_length = strlen($11);
    frame->debug_data = (uint8_t *) $11;
    $$ = (h2_frame_t *) frame;
  }
  ;

window_update_frame
  : TOKEN_WINDOW_UPDATE frame_options
  TOKEN_INCREMENT TOKEN_COLON TOKEN_NUMBER {
    h2_frame_window_update_t * frame = (h2_frame_window_update_t *) h2_frame_init(
      FRAME_TYPE_WINDOW_UPDATE, $2->flags, $2->stream_number);
    free($2);
    frame->increment = $5;
    $$ = (h2_frame_t *) frame;
  }
  ;

received_continuation_frame
  : TOKEN_CONTINUATION frame_options header_list {
    h2_frame_continuation_t * frame = (h2_frame_continuation_t *) h2_frame_init(
      FRAME_TYPE_CONTINUATION, $2->flags, $2->stream_number);
    free($2);
    apply_headers(frame, ctx->receiving_context, $3);
    $$ = (h2_frame_t *) frame;
  }
  ;

sent_continuation_frame
  : TOKEN_CONTINUATION frame_options header_list {
    h2_frame_continuation_t * frame = (h2_frame_continuation_t *) h2_frame_init(
      FRAME_TYPE_CONTINUATION, $2->flags, $2->stream_number);
    free($2);
    apply_headers(frame, ctx->sending_context, $3);
    $$ = (h2_frame_t *) frame;
  }
  ;

frame_padding
  :                                        { $$ = 0; }
  | TOKEN_PADDING TOKEN_COLON TOKEN_NUMBER { $$ = $3; }
  ;

frame_priority
  : priority_exclusive priority_stream_dependency priority_weight {
    $$ = malloc(sizeof(frame_priority_t));
    if ($1 == DEFAULT_PRIORITY_STREAM_EXCLUSIVE &&
        $2 == DEFAULT_PRIORITY_STREAM_DEPENDENCY &&
        $3 == DEFAULT_PRIORITY_WEIGHT) {
      $$->is_default = true;
    } else {
      $$->is_default = false;
    }
    $$->priority_exclusive = $1;
    $$->priority_stream_dependency = $2;
    $$->priority_weight = $3;
  }
  ;

priority_exclusive
  : { $$ = DEFAULT_PRIORITY_STREAM_EXCLUSIVE; }
  | TOKEN_EXCLUSIVE TOKEN_COLON TOKEN_NUMBER {
    $$ = $3;
  }
  ;

priority_stream_dependency
  : { $$ = DEFAULT_PRIORITY_STREAM_DEPENDENCY; }
  | TOKEN_STREAM_DEPENDENCY TOKEN_COLON TOKEN_NUMBER {
    $$ = $3;
  }
  ;

priority_weight
  : { $$ = DEFAULT_PRIORITY_WEIGHT; }
  | TOKEN_WEIGHT TOKEN_COLON TOKEN_NUMBER {
    $$ = $3;
  }
  ;

header_list
  : { $$ = header_list_init(NULL); }
  | header_list TOKEN_STRING TOKEN_COLON TOKEN_STRING {
    header_list_push($1, $2, strlen($2), true, $4, strlen($4), true);
    $$ = $1;
  }

settings_list
  : { $$ = NULL; }
  | settings_list TOKEN_SETTING_ID TOKEN_COLON TOKEN_NUMBER {
    settings_list_t * next = malloc(sizeof(settings_list_t));
    next->setting.id = $2;
    next->setting.value = $4;
    next->next = NULL;
    settings_list_t * curr = $1;
    if (!curr) {
      $$ = next;
    } else {
      while (curr->next) {
        curr = curr->next;
      }
      curr->next = next;
      $$ = $1;
    }
  }
  ;

frame_options
  : frame_flags frame_stream_number {
    $$ = malloc(sizeof(frame_options_t));
    $$->flags = $1;
    $$->stream_number = $2;
  }
  ;

frame_flags
  :                              { $$ = 0; }
  | frame_flags TOKEN_FRAME_FLAG { $$ = $1 | $2; }
  ;

frame_stream_number
  :                      { $$ = 0; }
  | TOKEN_STREAM_NUMBER  { $$ = $1; }
  ;

%%

