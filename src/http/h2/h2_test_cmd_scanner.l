%{
#include "h2_frame.h"
#include "h2_test_cmd_parser.h"

#include <stdio.h>
#include <stdint.h>

%}

%option warn nodefault

%option reentrant noyywrap never-interactive
%option bison-bridge
%option yylineno

LPAREN      "("
RPAREN      ")"
COLON       ":"

HEX         0x[0-9]+
DECIMAL     [0-9]+
WS          [ \r\n\t]*

%%

{WS}            { /* Skip blanks. */ }
{DECIMAL}       { sscanf(yytext, "%u", &yylval->value); return TOKEN_NUMBER; }
{HEX}           { sscanf(yytext, "0x%x", &yylval->value); return TOKEN_NUMBER; }

{LPAREN}        { return TOKEN_LPAREN; }
{RPAREN}        { return TOKEN_RPAREN; }
{COLON}         { return TOKEN_COLON; }
send            { return TOKEN_SEND; }
recv            { return TOKEN_RECV; }
SETTINGS        { yylval->frame_type = FRAME_TYPE_SETTINGS; return TOKEN_FRAME_TYPE; }
HEADERS         { yylval->frame_type = FRAME_TYPE_HEADERS; return TOKEN_FRAME_TYPE; }
ACK             { yylval->frame_flag = FLAG_ACK; return TOKEN_FRAME_FLAG; }


HEADER_TABLE_SIZE       { yylval->setting_id = SETTINGS_HEADER_TABLE_SIZE; return TOKEN_SETTING_ID; }
ENABLE_PUSH             { yylval->setting_id = SETTINGS_ENABLE_PUSH; return TOKEN_SETTING_ID; }
MAX_CONCURRENT_STREAMS  { yylval->setting_id = SETTINGS_MAX_CONCURRENT_STREAMS; return TOKEN_SETTING_ID; }
INITIAL_WINDOW_SIZE     { yylval->setting_id = SETTINGS_INITIAL_WINDOW_SIZE; return TOKEN_SETTING_ID; }
MAX_FRAME_SIZE          { yylval->setting_id = SETTINGS_MAX_FRAME_SIZE; return TOKEN_SETTING_ID; }
MAX_HEADER_LIST_SIZE    { yylval->setting_id = SETTINGS_MAX_HEADER_LIST_SIZE; return TOKEN_SETTING_ID; }

.               {  }

%%

