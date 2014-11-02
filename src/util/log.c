#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/time.h>

#include "log.h"
#include "util.h"

static char * LEVEL_STR[] = {
  "FATAL",
  "ERROR",
  "WARN",
  "INFO",
  "DEBUG",
  "TRACE"
};

log_context_t * log_context_init(log_context_t * ctx, char * name, FILE * fp, int min_level, bool enabled)
{
  ctx->name = name;
  ctx->fp = fp;
  ctx->min_level = min_level;
  ctx->enabled = enabled;
  return ctx;
}

bool log_enabled(log_context_t * ctx)
{
  return ctx && ctx->enabled;
}

bool log_level_enabled(log_context_t * ctx, enum log_level_e level)
{
  return log_enabled(ctx) && level <= ctx->min_level;
}

void log_append(log_context_t * ctx, enum log_level_e level, char * format, ...)
{
  if (log_level_enabled(ctx, level)) {
    va_list ap;
    char buf[256];
    va_start(ap, format);

    if (vsnprintf(buf, 256, format, ap) < 0) {
      abort();
    }

    va_end(ap);

    size_t date_buf_length = TIME_WITH_MS_LEN + 1;
    char date_buf[date_buf_length];
    char * time_str = current_time_with_milliseconds(date_buf, date_buf_length);

    if (fprintf(ctx->fp, "%s\t%s\t[%s]\t%s\n", ctx->name, LEVEL_STR[level], time_str, buf) < 0) {
      abort();
    }

    va_end(ap);
  }
}

void log_buffer(log_context_t * log, enum log_level_e level, uint8_t * buffer, size_t length)
{
  for (size_t i = 0; i < length; i+=16) {
    size_t buf_len = 256;
    char buf[buf_len];
    buf[0] = '\0';
    size_t half_length = 128;
    char hex[half_length];
    hex[0] = '\0';
    char dec[half_length];
    dec[0] = '\0';
    for (size_t j = 0; j < 16 && i + j < length; j++) {
      if (j != 0 && j % 2 == 0) {
        strncat(hex, " ", half_length);
      }
      size_t single_len = 64;
      char single[single_len];
      uint8_t x = buffer[i + j];
      snprintf(single, single_len, "%02x", x);
      strncat(hex, single, half_length);
      if (isprint(x)) {
        snprintf(single, single_len, "%c", x);
        strncat(dec, single, half_length);
      } else {
        strncat(dec, ".", half_length);
      }
    }
    snprintf(buf, buf_len, "%-40s\t%-16s", hex, dec);
    log_append(log, level, buf);
  }
}


