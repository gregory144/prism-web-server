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

int yyerror(h2_frame_parser_t * parser, h2_test_cmd_list_t * * cmd_list, yyscan_t scanner, const char * msg) {
  UNUSED(parser);
  UNUSED(cmd_list);
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

#include "h2_frame.h"
#include "h2_test_cmd.h"

typedef struct settings_list_s {

  struct settings_list_s * next;

  h2_setting_t setting;

} settings_list_t;

}

%define api.pure
%define parse.error verbose
%define parse.lac full
%lex-param   { yyscan_t scanner }
%parse-param { h2_frame_parser_t * frame_parser }
%parse-param { h2_test_cmd_list_t * * cmd_list }
%parse-param { yyscan_t scanner }

%union {
  uint8_t frame_flag;
  enum frame_type_e frame_type;
  uint32_t value;
  h2_test_cmd_list_t * cmd_list;
  h2_frame_t * frame;
  h2_test_cmd_t * cmd;
  settings_list_t * settings_list;
  uint16_t setting_id;
}

%token TOKEN_LPAREN
%token TOKEN_RPAREN
%token TOKEN_NEWLINE
%token TOKEN_SETTINGS
%token TOKEN_SEND
%token TOKEN_RECV
%token TOKEN_COLON
%token <setting_id> TOKEN_SETTING_ID
%token <value> TOKEN_NUMBER
%token <frame_type> TOKEN_FRAME_TYPE
%token <frame_flag> TOKEN_FRAME_FLAG;

%type <cmd_list> command_list
%type <cmd> command
%type <frame> frame
%type <frame> settings_frame
%type <frame> frame_header
/*%type <frame> frame_payload*/
%type <settings_list> settings_payload
%type <frame_flag> frame_flags

%%

command_list
  : {
    $$ = *cmd_list;
  }
  | command_list command {
    *cmd_list = h2_test_cmd_list_append($1, $2);
    $$ = *cmd_list;
  }
  ;

command
  : TOKEN_SEND frame {
    $$ = malloc(sizeof(h2_test_cmd_t));
    $$->cmd = TEST_CMD_SEND;
    $$->frame = $2;
  }
  | TOKEN_RECV frame {
    $$ = malloc(sizeof(h2_test_cmd_t));
    $$->cmd = TEST_CMD_RECV;
    $$->frame = $2;
  }
  ;

frame
  : settings_frame { $$ = $1; }
  ;

settings_frame
  : frame_header settings_payload {
    h2_frame_settings_t * f = (h2_frame_settings_t *) $1;
    settings_list_t * curr = $2;
    f->num_settings = 0;
    while (curr) {
      h2_setting_t * s = &f->settings[f->num_settings++];
      if (f->num_settings > 6) {
        printf("Parsed too many settings\n");
        abort();
      }
      s->id = curr->setting.id;
      s->value = curr->setting.value;
      curr = curr->next;
    }
    $$ = $1;
  }
  ;

settings_payload
  : { $$ = NULL; }
  | settings_payload TOKEN_SETTING_ID TOKEN_COLON TOKEN_NUMBER {
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

frame_header
  : TOKEN_FRAME_TYPE {
    $$ = h2_frame_init(frame_parser, $1, 0, 0);
  }
  | TOKEN_FRAME_TYPE frame_flags {
    $$ = h2_frame_init(frame_parser, $1, $2, 0);
  }
  | TOKEN_FRAME_TYPE TOKEN_NUMBER {
    $$ = h2_frame_init(frame_parser, $1, 0, $2);
  }
  | TOKEN_FRAME_TYPE TOKEN_NUMBER frame_flags {
    $$ = h2_frame_init(frame_parser, $1, $3, $2);
  }
  ;

frame_flags
  :                              { $$ = 0; }
  | frame_flags TOKEN_FRAME_FLAG { $$ = $1 | $2; }
  ;

%%

