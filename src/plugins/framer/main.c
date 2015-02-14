#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <inttypes.h>

#include <uv.h>

#include "client.h"
#include "worker.h"
#include "plugin.h"

#include "log.h"
#include "util.h"
#include "http/http.h"
#include "http/h2/h2.h"
#include "http/request.h"

static void framer_plugin_start(struct plugin_t * plugin)
{
  log_append(plugin->log, LOG_INFO, "Framer plugin started");
}

static void framer_plugin_stop(struct plugin_t * plugin)
{
  log_append(plugin->log, LOG_INFO, "Framer plugin stopped");
}

static char * error_code_to_string(enum h2_error_code_e e)
{
  switch (e) {
    case H2_ERROR_NO_ERROR:
      return "NO_ERROR";

    case H2_ERROR_PROTOCOL_ERROR:
      return "PROTOCOL_ERROR";

    case H2_ERROR_INTERNAL_ERROR:
      return "INTERNAL_ERROR";

    case H2_ERROR_FLOW_CONTROL_ERROR:
      return "FLOW_CONTROL_ERROR";

    case H2_ERROR_SETTINGS_TIMEOUT:
      return "SETTINGS_TIMEOUT";

    case H2_ERROR_STREAM_CLOSED:
      return "STREAM_CLOSED";

    case H2_ERROR_FRAME_SIZE_ERROR:
      return "FRAME_SIZE_ERROR";

    case H2_ERROR_REFUSED_STREAM:
      return "REFUSED_STREAM";

    case H2_ERROR_CANCEL:
      return "CANCEL";

    case H2_ERROR_COMPRESSION_ERROR:
      return "COMPRESSION_ERROR";

    case H2_ERROR_CONNECT_ERROR:
      return "CONNECT_ERROR";

    case H2_ERROR_ENHANCE_YOUR_CALM:
      return "ENHANCE_YOUR_CALM";

    case H2_ERROR_INADEQUATE_SECURITY:
      return "INADEQUATE_SECURITY";

    case H2_ERROR_HTTP_1_1_REQUIRED:
      return "HTTP_1_1_REQUIRED";
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
      if (flags & FLAG_END_STREAM) {
        strncat(buf, "END_STREAM, ", buf_len);
      }

      if (flags & FLAG_END_SEGMENT) {
        strncat(buf, "END_SEGMENT, ", buf_len);
      }

      if (flags & FLAG_PADDED) {
        strncat(buf, "PADDED, ", buf_len);
      }

      break;

    case FRAME_TYPE_HEADERS:
      if (flags & FLAG_END_STREAM) {
        strncat(buf, "END_STREAM, ", buf_len);
      }

      if (flags & FLAG_END_SEGMENT) {
        strncat(buf, "END_SEGMENT, ", buf_len);
      }

      if (flags & FLAG_END_HEADERS) {
        strncat(buf, "END_HEADERS, ", buf_len);
      }

      if (flags & FLAG_PADDED) {
        strncat(buf, "PADDED, ", buf_len);
      }

      if (flags & FLAG_PRIORITY) {
        strncat(buf, "PRIORITY, ", buf_len);
      }

      break;

    case FRAME_TYPE_SETTINGS:
    case FRAME_TYPE_PING:
      if (flags & FLAG_ACK) {
        strncat(buf, "ACK, ", buf_len);
      }

      break;

    case FRAME_TYPE_PUSH_PROMISE:
      if (flags & FLAG_END_HEADERS) {
        strncat(buf, "END_HEADERS, ", buf_len);
      }

      if (flags & FLAG_PADDED) {
        strncat(buf, "PADDED, ", buf_len);
      }

      break;

    case FRAME_TYPE_CONTINUATION:
      if (flags & FLAG_END_HEADERS) {
        strncat(buf, "END_HEADERS, ", buf_len);
      }

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

static void log_frame(struct plugin_t * plugin, struct client_t * client,
                      h2_frame_t * frame, char * frame_options, bool incoming)
{
  char frame_flags[FLAGS_TO_STRING_BUF_LEN];
  flags_to_string(frame_flags, FLAGS_TO_STRING_BUF_LEN, frame);

  char * type = frame_type_to_string(frame->type);

  log_append(plugin->log, LOG_INFO, "%s %s [client: %" PRIu64 ", length: %" PRIu16
             ", stream id: %" PRIu32 ", flags: %s (%" PRIu8 ", 0x%02x)%s%s]",
             incoming ? ">IN " : "<OUT",
             type, client->id, frame->length, frame->stream_id, frame_flags, frame->flags, frame->flags,
             frame_options ? ", " : "", frame_options ? frame_options : ""
            );
}

static void framer_plugin_frame_data(struct plugin_t * plugin, struct client_t * client,
                                     h2_frame_data_t * frame, bool incoming)
{
  bool padded = frame->flags & FLAG_PADDED;
  size_t buf_len = 128;
  char padded_buf[buf_len];

  if (padded) {
    snprintf(padded_buf, buf_len, "padding: %" PRIu32 " octets",
             ((uint32_t)frame->padding_length) + 1);
    log_frame(plugin, client, (h2_frame_t *) frame, padded_buf, incoming);
  } else {
    log_frame(plugin, client, (h2_frame_t *) frame, NULL, incoming);
  }
}

static void framer_plugin_frame_headers(struct plugin_t * plugin, struct client_t * client,
                                        h2_frame_headers_t * frame, bool incoming)
{
  bool padded = frame->flags & FLAG_PADDED;
  bool priority = frame->flags & FLAG_PRIORITY;
  size_t buf_len = 128;
  char padded_buf[buf_len];
  char priority_buf[buf_len];

  if (padded) {
    snprintf(padded_buf, buf_len, "padding: %" PRIu32 " octets",
             ((uint32_t)frame->padding_length) + 1);
  }

  if (priority) {
    snprintf(priority_buf, buf_len, "priority: (dependency: %" PRIu32", weight: %"
             PRIu32 ", exclusive: %s)", frame->priority_stream_dependency,
             ((uint32_t)frame->priority_weight) + 1,
             frame->priority_exclusive ? "yes" : "no");
  }

  if (padded && priority) {
    char buf[buf_len * 2];
    snprintf(buf, buf_len * 2, "%s, %s", padded_buf, priority_buf);
    log_frame(plugin, client, (h2_frame_t *) frame, buf, incoming);
  } else if (padded) {
    log_frame(plugin, client, (h2_frame_t *) frame, padded_buf, incoming);
  } else if (priority) {
    log_frame(plugin, client, (h2_frame_t *) frame, priority_buf, incoming);
  } else {
    log_frame(plugin, client, (h2_frame_t *) frame, NULL, incoming);
  }
}

static void framer_plugin_frame_push_promise(struct plugin_t * plugin, struct client_t * client,
    h2_frame_push_promise_t * frame, bool incoming)
{
  bool padded = frame->flags & FLAG_PADDED;
  size_t buf_len = 256;
  char buf[buf_len];
  snprintf(buf, buf_len, "promised stream id: %" PRIu32, frame->promised_stream_id);

  if (padded) {
    size_t padded_buf_len = 128;
    char padded_buf[padded_buf_len];
    snprintf(padded_buf, buf_len, ", padding: %" PRIu32 " octets", ((uint32_t)frame->padding_length) + 1);
    strncat(buf, padded_buf, buf_len);
  }

  log_frame(plugin, client, (h2_frame_t *) frame, buf, incoming);
}

static void framer_plugin_frame_priority(struct plugin_t * plugin, struct client_t * client,
    h2_frame_priority_t * frame, bool incoming)
{
  size_t buf_len = 128;
  char priority_buf[buf_len];
  snprintf(priority_buf, buf_len, "priority: (dependency: %" PRIu32", weight: %"
           PRIu32 ", exclusive: %s)", frame->priority_stream_dependency,
           ((uint32_t)frame->priority_weight) + 1,
           frame->priority_exclusive ? "yes" : "no");
  log_frame(plugin, client, (h2_frame_t *) frame, priority_buf, incoming);
}

static void framer_plugin_frame_rst_stream(struct plugin_t * plugin,
    struct client_t * client, h2_frame_rst_stream_t * frame, bool incoming)
{
  size_t buf_len = 128;
  char buf[buf_len];
  snprintf(buf, buf_len, "error: %s", error_code_to_string(frame->error_code));
  log_frame(plugin, client, (h2_frame_t *) frame, buf, incoming);
}

static void framer_plugin_frame_settings(struct plugin_t * plugin,
    struct client_t * client, h2_frame_settings_t * frame, bool incoming)
{
  size_t buf_len = 1024;
  char buf[buf_len];
  buf[0] = '\0';

  if (!frame->flags & FLAG_ACK) {
    h2_t * h2 = client->connection->handler;
    size_t setting_buf_len = 128;
    char setting_buf[setting_buf_len];
    bool first = true;

    for (size_t i = 0; i < frame->num_settings; i++) {
      h2_setting_t * setting = &frame->settings[i];

      switch (setting->id) {
        case SETTINGS_HEADER_TABLE_SIZE:
          if (incoming) {
            snprintf(setting_buf, setting_buf_len, "%sheader table size: %zd -> %" PRIu32,
                     !first ? ", " : "", h2->header_table_size, setting->value);
          } else {
            snprintf(setting_buf, setting_buf_len, "%sheader table size: %" PRIu32,
                     !first ? ", " : "", setting->value);
          }

          break;

        case SETTINGS_ENABLE_PUSH:
          if (incoming) {
            snprintf(setting_buf, setting_buf_len, "%senable push: %s -> %s",
                     !first ? ", " : "", h2->enable_push ? "yes" : "no", setting->value ? "yes" : "no");
          } else {
            snprintf(setting_buf, setting_buf_len, "%senable push: %s",
                     !first ? ", " : "", setting->value ? "yes" : "no");
          }

          break;

        case SETTINGS_MAX_CONCURRENT_STREAMS:
          if (incoming) {
            snprintf(setting_buf, setting_buf_len, "%smax concurrent streams: %zd -> %" PRIu32,
                     !first ? ", " : "", h2->max_concurrent_streams, setting->value);
          } else {
            snprintf(setting_buf, setting_buf_len, "%smax concurrent streams: %" PRIu32,
                     !first ? ", " : "", setting->value);
          }

          break;

        case SETTINGS_INITIAL_WINDOW_SIZE:
          if (incoming) {
            snprintf(setting_buf, setting_buf_len, "%sinitial window size: %zd -> %" PRIu32,
                     !first ? ", " : "", h2->initial_window_size, setting->value);
          } else {
            snprintf(setting_buf, setting_buf_len, "%sinitial window size: %" PRIu32,
                     !first ? ", " : "", setting->value);
          }

          break;

        case SETTINGS_MAX_FRAME_SIZE:
          if (incoming) {
            snprintf(setting_buf, setting_buf_len, "%smax frame size: %zd -> %" PRIu32,
                     !first ? ", " : "", h2->max_frame_size, setting->value);
          } else {
            snprintf(setting_buf, setting_buf_len, "%smax frame size: %" PRIu32,
                     !first ? ", " : "", setting->value);
          }

          break;

        case SETTINGS_MAX_HEADER_LIST_SIZE:
          if (incoming) {
            snprintf(setting_buf, setting_buf_len, "%smax header list size: %zd -> %" PRIu32,
                     !first ? ", " : "", h2->max_header_list_size, setting->value);
          } else {
            snprintf(setting_buf, setting_buf_len, "%smax header list size: %" PRIu32,
                     !first ? ", " : "", setting->value);
          }

          break;

        default:
          snprintf(setting_buf, setting_buf_len, "%sunknown setting: %d: %" PRIu32,
                   !first ? ", " : "", setting->id, setting->value);
      }

      strncat(buf, setting_buf, buf_len);
      first = false;
    }
  }

  log_frame(plugin, client, (h2_frame_t *) frame, strlen(buf) > 0 ? buf : NULL, incoming);
}

static void framer_plugin_frame_ping(struct plugin_t * plugin,
                                     struct client_t * client, h2_frame_ping_t * frame, bool incoming)
{
  size_t buf_len = 64;
  char buf[buf_len];
  snprintf(buf, buf_len, "opaque data: 0x%02x%02x%02x%02x%02x%02x%02x%02x",
           frame->opaque_data[0],
           frame->opaque_data[1],
           frame->opaque_data[2],
           frame->opaque_data[3],
           frame->opaque_data[4],
           frame->opaque_data[5],
           frame->opaque_data[6],
           frame->opaque_data[7]
          );
  log_frame(plugin, client, (h2_frame_t *) frame, buf, incoming);
}

static void framer_plugin_frame_goaway(struct plugin_t * plugin,
                                       struct client_t * client, h2_frame_goaway_t * frame, bool incoming)
{
  size_t buf_len = 64 + frame->debug_data_length;
  char buf[buf_len];
  snprintf(buf, buf_len, "last stream ID: %" PRIu32 ", error: %s",
           frame->last_stream_id,
           error_code_to_string(frame->error_code)
          );

  if (frame->debug_data_length) {
    strncat(buf, ", debug data: <", buf_len);
    strncat(buf, (char *) frame->debug_data, buf_len);
    strncat(buf, ">", buf_len);
  }

  log_frame(plugin, client, (h2_frame_t *) frame, buf, incoming);
}

static void framer_plugin_frame_window_update(struct plugin_t * plugin,
    struct client_t * client, h2_frame_window_update_t * frame, bool incoming)
{
  size_t buf_len = 64;
  char buf[buf_len];
  buf[0] = '\0';
  long increment = (long) frame->increment;
  h2_t * h2 = client->connection->handler;

  if (frame->stream_id) {
    if (!h2_stream_closed(h2, frame->stream_id)) {
      h2_stream_t * stream = h2_stream_get(h2, frame->stream_id);
      long window = incoming ? stream->outgoing_window_size : stream->incoming_window_size;
      snprintf(buf, buf_len, "increment stream window: %zd -> %zd by %zd",
               window, window + increment, increment
              );
    }
  } else {
    long window = incoming ? h2->outgoing_window_size : h2->incoming_window_size;
    snprintf(buf, buf_len, "increment connection window: %zd -> %zd by %zd",
             window, window + increment, increment
            );
  }

  log_frame(plugin, client, (h2_frame_t *) frame, buf, incoming);
}

static void framer_plugin_frame_continuation(struct plugin_t * plugin,
    struct client_t * client, h2_frame_continuation_t * frame, bool incoming)
{
  log_frame(plugin, client, (h2_frame_t *) frame, NULL, incoming);
}

static bool framer_plugin_handler(struct plugin_t * plugin, struct client_t * client, enum plugin_callback_e cb, va_list args)
{
  switch (cb) {
    case INCOMING_FRAME_DATA:
      {
        h2_frame_data_t * frame = va_arg(args, h2_frame_data_t *);
        framer_plugin_frame_data(plugin, client, frame, true);
        return false;
      }

    case INCOMING_FRAME_HEADERS:
      {
        h2_frame_headers_t * frame = va_arg(args, h2_frame_headers_t *);
        framer_plugin_frame_headers(plugin, client, frame, true);
        return false;
      }

    case INCOMING_FRAME_PUSH_PROMISE:
      {
        h2_frame_push_promise_t * frame = va_arg(args, h2_frame_push_promise_t *);
        framer_plugin_frame_push_promise(plugin, client, frame, true);
        return false;
      }

    case INCOMING_FRAME_PRIORITY:
      {
        h2_frame_priority_t * frame = va_arg(args, h2_frame_priority_t *);
        framer_plugin_frame_priority(plugin, client, frame, true);
        return false;
      }

    case INCOMING_FRAME_RST_STREAM:
      {
        h2_frame_rst_stream_t * frame = va_arg(args, h2_frame_rst_stream_t *);
        framer_plugin_frame_rst_stream(plugin, client, frame, true);
        return false;
      }

    case INCOMING_FRAME_SETTINGS:
      {
        h2_frame_settings_t * frame = va_arg(args, h2_frame_settings_t *);
        framer_plugin_frame_settings(plugin, client, frame, true);
        return false;
      }

    case INCOMING_FRAME_PING:
      {
        h2_frame_ping_t * frame = va_arg(args, h2_frame_ping_t *);
        framer_plugin_frame_ping(plugin, client, frame, true);
        return false;
      }

    case INCOMING_FRAME_GOAWAY:
      {
        h2_frame_goaway_t * frame = va_arg(args, h2_frame_goaway_t *);
        framer_plugin_frame_goaway(plugin, client, frame, true);
        return false;
      }

    case INCOMING_FRAME_WINDOW_UPDATE:
      {
        h2_frame_window_update_t * frame = va_arg(args, h2_frame_window_update_t *);
        framer_plugin_frame_window_update(plugin, client, frame, true);
        return false;
      }

    case INCOMING_FRAME_CONTINUATION:
      {
        h2_frame_continuation_t * frame = va_arg(args, h2_frame_continuation_t *);
        framer_plugin_frame_continuation(plugin, client, frame, true);
        return false;
      }

    case OUTGOING_FRAME_DATA_SENT:
      {
        h2_frame_data_t * frame = va_arg(args, h2_frame_data_t *);
        framer_plugin_frame_data(plugin, client, frame, false);
        return false;
      }

    case OUTGOING_FRAME_HEADERS_SENT:
      {
        h2_frame_headers_t * frame = va_arg(args, h2_frame_headers_t *);
        framer_plugin_frame_headers(plugin, client, frame, false);
        return false;
      }

    case OUTGOING_FRAME_PUSH_PROMISE_SENT:
      {
        h2_frame_push_promise_t * frame = va_arg(args, h2_frame_push_promise_t *);
        framer_plugin_frame_push_promise(plugin, client, frame, false);
        return false;
      }

    case OUTGOING_FRAME_PRIORITY_SENT:
      {
        h2_frame_priority_t * frame = va_arg(args, h2_frame_priority_t *);
        framer_plugin_frame_priority(plugin, client, frame, false);
        return false;
      }

    case OUTGOING_FRAME_RST_STREAM_SENT:
      {
        h2_frame_rst_stream_t * frame = va_arg(args, h2_frame_rst_stream_t *);
        framer_plugin_frame_rst_stream(plugin, client, frame, false);
        return false;
      }

    case OUTGOING_FRAME_SETTINGS_SENT:
      {
        h2_frame_settings_t * frame = va_arg(args, h2_frame_settings_t *);
        framer_plugin_frame_settings(plugin, client, frame, false);
        return false;
      }

    case OUTGOING_FRAME_PING_SENT:
      {
        h2_frame_ping_t * frame = va_arg(args, h2_frame_ping_t *);
        framer_plugin_frame_ping(plugin, client, frame, false);
        return false;
      }

    case OUTGOING_FRAME_GOAWAY_SENT:
      {
        h2_frame_goaway_t * frame = va_arg(args, h2_frame_goaway_t *);
        framer_plugin_frame_goaway(plugin, client, frame, false);
        return false;
      }

    case OUTGOING_FRAME_WINDOW_UPDATE_SENT:
      {
        h2_frame_window_update_t * frame = va_arg(args, h2_frame_window_update_t *);
        framer_plugin_frame_window_update(plugin, client, frame, false);
        return false;
      }

    case OUTGOING_FRAME_CONTINUATION_SENT:
      {
        h2_frame_continuation_t * frame = va_arg(args, h2_frame_continuation_t *);
        framer_plugin_frame_continuation(plugin, client, frame, false);
        return false;
      }

    default:
      return false;
  }
}

void plugin_initialize(struct plugin_t * plugin, struct worker_t * worker)
{
  UNUSED(worker);

  plugin->handlers->start = framer_plugin_start;
  plugin->handlers->stop = framer_plugin_stop;
  plugin->handlers->handle = framer_plugin_handler;
}

