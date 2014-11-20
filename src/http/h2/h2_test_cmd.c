#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "h2_test_cmd.h"
#include "h2_test_cmd_parser.h"
#include "h2_test_cmd_scanner.h"

#ifndef YY_TYPEDEF_YY_SCANNER_T
#define YY_TYPEDEF_YY_SCANNER_T
typedef void * yyscan_t;
#endif

int yyparse(h2_test_cmd_context_t * ctx, yyscan_t scanner);

h2_test_cmd_list_t * h2_test_cmd_list_parse(FILE * fp)
{
  h2_test_cmd_context_t ctx;
  ctx.sending_context = hpack_context_init(DEFAULT_HEADER_TABLE_SIZE, NULL);
  ctx.receiving_context = hpack_context_init(DEFAULT_HEADER_TABLE_SIZE, NULL);
  yyscan_t scanner;

  if (yylex_init(&scanner)) {
    // couldn't initialize
    return NULL;
  }

  YY_BUFFER_STATE state = yy_create_buffer(fp, YY_BUF_SIZE, scanner);
  yy_switch_to_buffer(state, scanner);

  if (yyparse(&ctx, scanner)) {
    // error parsing
    return NULL;
  }

  yy_delete_buffer(state, scanner);

  yylex_destroy(scanner);

  hpack_context_free(ctx.sending_context);
  hpack_context_free(ctx.receiving_context);

  return ctx.list;
}

h2_test_cmd_list_t * h2_test_cmd_list_append(h2_test_cmd_list_t * test_cmd, h2_test_cmd_t * cmd)
{
  h2_test_cmd_list_t * next = malloc(sizeof(h2_test_cmd_list_t));
  next->cmd = cmd;
  next->next = NULL;

  h2_test_cmd_list_t * curr = test_cmd;
  if (!curr) {
    return next;
  }
  while (curr->next) {
    curr = curr->next;
  }
  curr->next = next;

  return test_cmd;
}
