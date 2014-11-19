%{
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "h2_frame.h"
#include "h2_test_cmd_parser.h"

char * strdup(char *);

%}

%option warn nodefault

%option reentrant noyywrap never-interactive
%option bison-bridge
%option yylineno

LPAREN      "("
RPAREN      ")"
COLON       ":"
COMMA       ","

HEX         0x[0-9A-F]+
DECIMAL     [0-9]+
WS          [ \r\n\t]*
L           [a-zA-Z_]

%%

{WS}            { /* Skip blanks. */ }
#.*\r?\n        { /* skip comments */ }
S{DECIMAL}      { sscanf(yytext, "S%u", &yylval->value_bt); return TOKEN_STREAM_NUMBER; }
S{HEX}           { sscanf(yytext, "S%x", &yylval->value_bt); return TOKEN_STREAM_NUMBER; }
{DECIMAL}       { sscanf(yytext, "%u", &yylval->value_bt); return TOKEN_NUMBER; }
{HEX}           { sscanf(yytext, "%x", &yylval->value_bt); return TOKEN_NUMBER; }

{LPAREN}        { return TOKEN_LPAREN; }
{RPAREN}        { return TOKEN_RPAREN; }
{COLON}         { return TOKEN_COLON; }
{COMMA}         { return TOKEN_COMMA; }
send            { return TOKEN_SEND; }
recv            { return TOKEN_RECV; }

DATA            { return TOKEN_DATA; }
HEADERS         { return TOKEN_HEADERS; }
PRIORITY        { return TOKEN_PRIORITY; }
RST_STREAM      { return TOKEN_RST_STREAM; }
SETTINGS        { return TOKEN_SETTINGS; }
PUSH_PROMISE    { return TOKEN_PUSH_PROMISE; }
PING            { return TOKEN_PING; }
GOAWAY          { return TOKEN_GOAWAY; }
WINDOW_UPDATE   { return TOKEN_WINDOW_UPDATE; }
CONTINUATION    { return TOKEN_CONTINUATION; }

PROMISED_STREAM_ID { return TOKEN_PROMISED_STREAM_ID; }
PROMISE         { return TOKEN_PROMISED_STREAM_ID; }
EXCLUSIVE       { return TOKEN_EXCLUSIVE; }
STREAM_DEPENDENCY { return TOKEN_STREAM_DEPENDENCY; }
WEIGHT          { return TOKEN_WEIGHT; }
PADDING         { return TOKEN_PADDING; }
LAST_STREAM_ID  { return TOKEN_LAST_STREAM_ID; }
LAST_STREAM     { return TOKEN_LAST_STREAM_ID; }
ERROR_CODE      { return TOKEN_ERROR_CODE; }
ERROR           { return TOKEN_ERROR_CODE; }
ADDITIONAL_DATA { return TOKEN_ADDITIONAL_DATA; }
INCREMENT       { return TOKEN_INCREMENT; }

ACK             { yylval->frame_flag_bt = FLAG_ACK; return TOKEN_FRAME_FLAG; }
END_HEADERS     { yylval->frame_flag_bt = FLAG_END_HEADERS; return TOKEN_FRAME_FLAG; }
END_STREAM      { yylval->frame_flag_bt = FLAG_END_STREAM; return TOKEN_FRAME_FLAG; }


NO_ERROR            { yylval->value_bt = H2_ERROR_NO_ERROR; return TOKEN_ERROR_CODE_VALUE; }
PROTOCOL_ERROR      { yylval->value_bt = H2_ERROR_PROTOCOL_ERROR; return TOKEN_ERROR_CODE_VALUE; }
INTERNAL_ERROR      { yylval->value_bt = H2_ERROR_INTERNAL_ERROR; return TOKEN_ERROR_CODE_VALUE; }
FLOW_CONTROL_ERROR  { yylval->value_bt = H2_ERROR_FLOW_CONTROL_ERROR; return TOKEN_ERROR_CODE_VALUE; }
SETTINGS_TIMEOUT    { yylval->value_bt = H2_ERROR_SETTINGS_TIMEOUT; return TOKEN_ERROR_CODE_VALUE; }
STREAM_CLOSED       { yylval->value_bt = H2_ERROR_STREAM_CLOSED; return TOKEN_ERROR_CODE_VALUE; }
FRAME_SIZE_ERROR    { yylval->value_bt = H2_ERROR_FRAME_SIZE_ERROR; return TOKEN_ERROR_CODE_VALUE; }
REFUSED_STREAM      { yylval->value_bt = H2_ERROR_REFUSED_STREAM; return TOKEN_ERROR_CODE_VALUE; }
CANCEL              { yylval->value_bt = H2_ERROR_CANCEL; return TOKEN_ERROR_CODE_VALUE; }
COMPRESSION_ERROR   { yylval->value_bt = H2_ERROR_COMPRESSION_ERROR; return TOKEN_ERROR_CODE_VALUE; }
CONNECT_ERROR       { yylval->value_bt = H2_ERROR_CONNECT_ERROR; return TOKEN_ERROR_CODE_VALUE; }
ENHANCE_YOUR_CALM   { yylval->value_bt = H2_ERROR_ENHANCE_YOUR_CALM; return TOKEN_ERROR_CODE_VALUE; }
INADEQUATE_SECURITY { yylval->value_bt = H2_ERROR_INADEQUATE_SECURITY; return TOKEN_ERROR_CODE_VALUE; }

HEADER_TABLE_SIZE       { yylval->setting_id_bt = SETTINGS_HEADER_TABLE_SIZE; return TOKEN_SETTING_ID; }
ENABLE_PUSH             { yylval->setting_id_bt = SETTINGS_ENABLE_PUSH; return TOKEN_SETTING_ID; }
MAX_CONCURRENT_STREAMS  { yylval->setting_id_bt = SETTINGS_MAX_CONCURRENT_STREAMS; return TOKEN_SETTING_ID; }
INITIAL_WINDOW_SIZE     { yylval->setting_id_bt = SETTINGS_INITIAL_WINDOW_SIZE; return TOKEN_SETTING_ID; }
MAX_FRAME_SIZE          { yylval->setting_id_bt = SETTINGS_MAX_FRAME_SIZE; return TOKEN_SETTING_ID; }
MAX_HEADER_LIST_SIZE    { yylval->setting_id_bt = SETTINGS_MAX_HEADER_LIST_SIZE; return TOKEN_SETTING_ID; }

L?\"(\\.|[^\\"])*\"     {
                            size_t start = 1;
                            size_t len = strlen(yytext) - 2;
                            char * buf = malloc(len + 1);
                            memcpy(buf, &yytext[start], len);
                            buf[len] = '\0';
                            yylval->string_bt = buf;
                            return TOKEN_STRING; }
[a-zA-Z][-a-zA-Z0-9]    { yylval->string_bt = strdup(yytext); return TOKEN_STRING; }

\.                      { return TOKEN_DOT; }
.                       {  }

%%

