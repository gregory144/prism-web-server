#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <sys/time.h>

#include "log.h"
#include "util.h"

static char * LEVEL_STR[] = {
  NULL,
  "TRACE",
  "DEBUG",
  "INFO",
  "WARN",
  "ERROR",
  "FATAL"
};

log_context_t * log_context_init(log_context_t * ctx, char * name, FILE * fp, int min_level, bool enabled)
{
  ctx->name = name;
  ctx->fp = fp;
  ctx->min_level = min_level;
  ctx->enabled = enabled;
  ctx->pid = getpid();
  return ctx;
}

bool log_enabled(log_context_t * ctx)
{
  return ctx && ctx->enabled;
}

bool log_level_enabled(log_context_t * ctx, enum log_level_e level)
{
  return log_enabled(ctx) && level != 0 && level >= ctx->min_level;
}

static void log_append_string(log_context_t * ctx, enum log_level_e level, char * str)
{
  if (log_level_enabled(ctx, level)) {
    size_t date_buf_length = TIME_WITH_MS_LEN + 1;
    char date_buf[date_buf_length];
    char * time_str = current_time_with_milliseconds(date_buf, date_buf_length);

    if (fprintf(ctx->fp, "%d\t%s\t%s\t[%s]\t%s\n", ctx->pid, ctx->name, LEVEL_STR[level], time_str, str) < 0) {
      abort();
    }
  }
}

void log_append(log_context_t * ctx, enum log_level_e level, char * format, ...)
{
  if (log_level_enabled(ctx, level)) {
    va_list ap;
    size_t buf_length = 1024;
    char buf[buf_length];
    va_start(ap, format);

    if (vsnprintf(buf, buf_length, format, ap) < 0) {
      abort();
    }

    va_end(ap);

    log_append_string(ctx, level, buf);
  }
}

void log_buffer(log_context_t * ctx, enum log_level_e level, uint8_t * buffer, size_t length)
{
  for (size_t i = 0; i < length; i+=16) {
    size_t half_buf_length = 64;
    size_t hex_length = 0;
    size_t dec_length = 0;

    char hex[half_buf_length];
    char dec[half_buf_length];
    for (size_t j = 0; j < 16 && i + j < length; j++) {
      if (j != 0 && j % 2 == 0) {
        hex_length += snprintf(hex + hex_length, half_buf_length, " ");
      }
      uint8_t x = buffer[i + j];

      hex_length += snprintf(hex + hex_length, half_buf_length, "%02x", x);
      if (isprint(x)) {
        dec_length += snprintf(dec + dec_length, half_buf_length, "%c", x);
      } else {
        dec_length += snprintf(dec + dec_length, half_buf_length, ".");
      }
    }

    size_t out_length = 128;
    char out[out_length];
    snprintf(out, out_length, "%-40s\t%-16s", hex, dec);
    log_append_string(ctx, level, out);
  }
}


enum log_level_e log_level_from_string(char * s)
{
  for (size_t i = 1; i < sizeof(LEVEL_STR) / sizeof(char*); i++) {
    if (strcmp(s, LEVEL_STR[i]) == 0) {
      return (enum log_level_e) i;
    }
  }
  return 0;
}
