#ifndef HTTP_PLUGIN_CALLBACKS_H
#define HTTP_PLUGIN_CALLBACKS_H

enum plugin_callback_e {
  HANDLE_REQUEST,
  HANDLE_DATA,
  POST_CONSTRUCT_FRAME
};

typedef bool (*plugin_handler_va_cb)(void * plugin, enum plugin_callback_e cb, va_list args);
typedef bool (*plugin_handler_cb)(void * plugin, enum plugin_callback_e cb, ...);

#endif
