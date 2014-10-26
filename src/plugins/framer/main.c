#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <inttypes.h>

#include <uv.h>

#include "server.h"
#include "plugin.h"

#include "log.h"
#include "util.h"
#include "http/http.h"
#include "http/h2/h2.h"
#include "http/request.h"

static void framer_plugin_start(plugin_t * plugin)
{
  log_append(plugin->log, LOG_INFO, "framer plugin started");
}

static void framer_plugin_stop(plugin_t * plugin)
{
  log_append(plugin->log, LOG_INFO, "framer plugin stopped");
}

/**
 * Caller should not free the returned string
 */
static char * frame_type_to_string(enum frame_type_e t)
{
  switch (t) {
    case FRAME_TYPE_DATA:
      return "DATA";
    case FRAME_TYPE_HEADERS:
      return "HEADERS";
    case FRAME_TYPE_PRIORITY:
      return "PRIORITY";
    case FRAME_TYPE_RST_STREAM:
      return "RST_STREAM";
    case FRAME_TYPE_SETTINGS:
      return "SETTINGS";
    case FRAME_TYPE_PUSH_PROMISE:
      return "PUSH_PROMISE";
    case FRAME_TYPE_PING:
      return "PING";
    case FRAME_TYPE_GOAWAY:
      return "GOAWAY";
    case FRAME_TYPE_WINDOW_UPDATE:
      return "WINDOW_UPDATE";
    case FRAME_TYPE_CONTINUATION:
      return "CONTINUATION";
  }
  return "UNKNOWN";
}

#define FLAGS_TO_STRING_BUF_LEN 128

static void flags_to_string(char * buf, size_t buf_len, h2_frame_t * frame)
{
  buf[0] = '\0';
  uint8_t flags = frame->flags;
  switch (frame->type) {
    case FRAME_TYPE_DATA:
      if (flags & FLAG_END_STREAM) { strncat(buf, "END_STREAM, ", buf_len); }
      if (flags & FLAG_END_SEGMENT) { strncat(buf, "END_SEGMENT, ", buf_len); }
      if (flags & FLAG_PADDED) { strncat(buf, "END_PADDED, ", buf_len); }
      break;
    case FRAME_TYPE_HEADERS:
      if (flags & FLAG_END_STREAM) { strncat(buf, "END_STREAM, ", buf_len); }
      if (flags & FLAG_END_SEGMENT) { strncat(buf, "END_SEGMENT, ", buf_len); }
      if (flags & FLAG_END_HEADERS) { strncat(buf, "END_HEADERS, ", buf_len); }
      if (flags & FLAG_PADDED) { strncat(buf, "PADDED, ", buf_len); }
      if (flags & FLAG_PRIORITY) { strncat(buf, "PRIORITY, ", buf_len); }
      break;
    case FRAME_TYPE_SETTINGS:
    case FRAME_TYPE_PING:
      if (flags & FLAG_ACK) { strncat(buf, "ACK, ", buf_len); }
      break;
    case FRAME_TYPE_PUSH_PROMISE:
      if (flags & FLAG_END_HEADERS) { strncat(buf, "END_HEADERS, ", buf_len); }
      if (flags & FLAG_PADDED) { strncat(buf, "PADDED, ", buf_len); }
      break;
    case FRAME_TYPE_CONTINUATION:
      if (flags & FLAG_END_HEADERS) { strncat(buf, "END_HEADERS, ", buf_len); }
      break;
    default:
      break;
  }
  if (buf[0] == '\0') {
    strncat(buf, "none", buf_len);
  } else {
    // remove the last ", "
    buf[strlen(buf) - 2] = '\0';
  }
}

/*#define FRAME_TO_STRING_BUF_LEN 1024*/

/*static void frame_to_string(char * buf, size_t buf_len, h2_frame_t * frame, uint8_t * payload)*/
/*{*/
  /*buf[0] = '\0';*/
  /*uint8_t flags = frame->flags;*/
  /*switch (frame->type) {*/
    /*case FRAME_TYPE_DATA:*/
    /*{*/
      /*if (flags & FLAG_PADDED) {*/
        /*uint8_t padding_length = get_bits8(payload, 0xFF);*/
        /*snprintf(buf, buf_len, "padding length: %" PRIu8, padding_length);*/
      /*}*/
      /*break;*/
    /*}*/
    /*case FRAME_TYPE_HEADERS:*/
    /*{*/
      /*if (flags & FLAG_PADDED) {*/
        /*uint8_t padding_length = get_bits8(payload, 0xFF);*/
        /*snprintf(buf, buf_len, "padding length: %" PRIu8, padding_length);*/
      /*}*/
      /*if (flags & FLAG_PRIORITY) {*/
        /*uint32_t dependency = get_bits32(payload, 0xFF);*/
        /*snprintf(buf, buf_len, "padding length: %" PRIu8, padding_length);*/
      /*}*/
      /*break;*/
    /*}*/
    /*case FRAME_TYPE_SETTINGS:*/
    /*case FRAME_TYPE_PING:*/
      /*if (flags & FLAG_ACK) { strncat(buf, "ACK, ", buf_len); }*/
      /*break;*/
    /*case FRAME_TYPE_PUSH_PROMISE:*/
      /*if (flags & FLAG_END_HEADERS) { strncat(buf, "END_HEADERS, ", buf_len); }*/
      /*if (flags & FLAG_PADDED) { strncat(buf, "PADDED, ", buf_len); }*/
      /*break;*/
    /*case FRAME_TYPE_CONTINUATION:*/
      /*if (flags & FLAG_END_HEADERS) { strncat(buf, "END_HEADERS, ", buf_len); }*/
      /*break;*/
    /*default:*/
      /*break;*/
  /*}*/
/*}*/

static void framer_plugin_preprocess_incoming_frame(plugin_t * plugin, client_t * client,
    h2_frame_t * frame, uint8_t * payload)
{

  UNUSED(payload);

  char frame_flags[FLAGS_TO_STRING_BUF_LEN];
  flags_to_string(frame_flags, FLAGS_TO_STRING_BUF_LEN, frame);

  char * type = frame_type_to_string(frame->type);

  /*char frame_options[FRAME_TO_STRING_BUF_LEN];*/
  /*frame_to_string(frame_options, FRAME_TO_STRING_BUF_LEN, frame, payload);*/

  /*log_append(plugin->log, LOG_INFO, "> %s [client: %" PRIu64 ", length: %" PRIu16*/
      /*", stream id: %" PRIu32 ", flags: %s (%#02x)] [%s]",*/
      /*type, client->id, frame->length, frame->stream_id, frame_flags, frame->flags,*/
      /*frame_options*/
  /*);*/

  log_append(plugin->log, LOG_INFO, "> %s [client: %" PRIu64 ", length: %" PRIu16
      ", stream id: %" PRIu32 ", flags: %s (%" PRIu8 ", 0x%02x)]",
      type, client->id, frame->length, frame->stream_id, frame_flags, frame->flags, frame->flags
  );
}

static bool framer_plugin_handler(plugin_t * plugin, client_t * client, enum plugin_callback_e cb, va_list args)
{
  switch (cb) {
    case PREPROCESS_INCOMING_FRAME:
    {
      h2_frame_t * frame = va_arg(args, h2_frame_t *);
      uint8_t * payload = va_arg(args, uint8_t *);
      framer_plugin_preprocess_incoming_frame(plugin, client, frame, payload);
      return false;
    }
    default:
      return false;
  }
}

void plugin_initialize(plugin_t * plugin, server_t * server)
{
  UNUSED(server);

  plugin->handlers->start = framer_plugin_start;
  plugin->handlers->stop = framer_plugin_stop;
  plugin->handlers->handle = framer_plugin_handler;
}

