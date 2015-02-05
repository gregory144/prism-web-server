#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <linux/limits.h>

#include <uv.h>

#include "client.h"
#include "worker.h"
#include "plugin.h"

#include "log.h"
#include "util.h"
#include "multimap.h"
#include "http/http.h"

#define READ_BUF_SIZE 0x100000 // 2^20

struct accept_param_t {
  struct accept_param_t * next;

  char * key;

  char * value;

};

struct content_type_t {

  char * type;

  char * subtype;

};

struct accept_type_t {

  struct accept_type_t * next;

  char * type;
  char * subtype;

  struct accept_param_t * media_params;

  double weight;

  struct accept_param_t * ext_params;

};

struct file_server_t {

  log_context_t * log;

  struct worker_t * worker;

  struct plugin_t * plugin;

  multimap_t * type_map;

  struct content_type_t * default_content_type;

  char * cwd;
  size_t cwd_length;

};

struct file_server_request_t {

  struct file_server_t * file_server;

  char * path;

  uv_file fd;

  uv_loop_t * loop;

  uv_fs_t open_req;

  uv_fs_t stat_req;

  uv_buf_t buf;

  uv_fs_t read_req;

  uv_fs_t close_req;

  ssize_t content_length;

  ssize_t bytes_read;

  http_response_t * response;

} file_server_request_t;

static struct content_type_t * register_content_type(multimap_t * m,
    char * extension, char * type, char * subtype)
{
  struct content_type_t * t = malloc(sizeof(struct content_type_t));

  t->type = type;

  t->subtype = subtype;

  multimap_put(m, extension, t);

  return t;
}

static void files_plugin_init_type_map(struct file_server_t * fs)
{
  fs->type_map = multimap_init_with_string_keys();

  register_content_type(fs->type_map, "htm", "text", "html");
  register_content_type(fs->type_map, "html", "text", "html");
  register_content_type(fs->type_map, "txt", "text", "plain");
  register_content_type(fs->type_map, "text", "text", "plain");
  register_content_type(fs->type_map, "jpg", "image", "jpeg");
  register_content_type(fs->type_map, "jpeg", "image", "jpeg");
  register_content_type(fs->type_map, "gif", "image", "gif");
  register_content_type(fs->type_map, "png", "image", "png");
  register_content_type(fs->type_map, "log", "text", "plain");
  register_content_type(fs->type_map, "js", "application", "javascript");
  register_content_type(fs->type_map, "css", "text", "css");
  register_content_type(fs->type_map, "ttf", "application", "x-font-ttf");

  struct content_type_t * default_ct =
    register_content_type(fs->type_map, "bin", "application", "octet-stream");

  fs->default_content_type = default_ct;
}

static void files_plugin_start(struct plugin_t * plugin)
{
  struct file_server_t * file_server = plugin->data;

  size_t cwd_capacity = 256;
  char * cwd = malloc(cwd_capacity);

  while (getcwd(cwd, cwd_capacity) == NULL) {
    cwd_capacity *= 2;
    cwd = realloc(cwd, cwd_capacity);
  }

  size_t cwd_length = strlen(cwd);

  if (cwd_length + 1 >= cwd_capacity) {
    cwd = realloc(cwd, cwd_capacity + 1);
  }

  cwd_length++;
  cwd[cwd_length - 1] = '/';
  cwd[cwd_length] = 0;

  file_server->cwd = cwd;
  file_server->cwd_length = cwd_length;

  log_append(plugin->log, LOG_INFO, "Files plugin started");
}

static void noop(void * v)
{
  UNUSED(v);
}

static void files_plugin_stop(struct plugin_t * plugin)
{
  log_append(plugin->log, LOG_INFO, "Files plugin stopped");

  struct file_server_t * file_server = plugin->data;

  multimap_free(file_server->type_map, noop, free);

  free(file_server->cwd);
  free(file_server);
}

static void file_server_request_free(struct file_server_request_t * fs_request)
{
  if (fs_request->buf.base) {
    free(fs_request->buf.base);
  }

  if (fs_request->path) {
    free(fs_request->path);
  }

  free(fs_request);
}

static void file_server_uv_close_cb(uv_fs_t * req)
{
  struct file_server_request_t * fs_request = req->data;
  file_server_request_free(fs_request);
}

static void file_server_finish_request(struct file_server_request_t * fs_request)
{
  if (fs_request->fd >= 0) {
    uv_fs_close(fs_request->loop, &fs_request->close_req, fs_request->fd, file_server_uv_close_cb);
  } else {
    file_server_request_free(fs_request);
  }
}

static void file_server_read_file(struct file_server_request_t * fs_request, ssize_t offset);

static void file_server_uv_read_cb(uv_fs_t * req)
{
  struct file_server_request_t * fs_request = req->data;
  ssize_t nread = req->result;
  uv_fs_req_cleanup(req);

  uv_buf_t * buf = &fs_request->buf;
  http_response_t * response = fs_request->response;

  if (nread == UV_EOF || nread <= 0) {
    http_response_write_data(response, NULL, 0, true);
    file_server_finish_request(fs_request);
  } else {
    fs_request->bytes_read += nread;
    bool finished = fs_request->bytes_read >= fs_request->content_length;

    uint8_t * write_buf = malloc(nread);
    memcpy(write_buf, buf->base, nread);

    http_response_write_data(response, write_buf, nread, finished);

    if (finished) {
      file_server_finish_request(fs_request);
    } else {
      file_server_read_file(fs_request, fs_request->bytes_read);
    }
  }
}

static void file_server_read_file(struct file_server_request_t * fs_request, ssize_t offset)
{
  if (uv_fs_read(fs_request->loop, &fs_request->read_req, fs_request->fd, &fs_request->buf, 1, offset,
                 file_server_uv_read_cb)) {
    http_response_write_error(fs_request->response, 500);
    file_server_finish_request(fs_request);
  }
}

static char * file_extension(char * path)
{
  char * dot = strrchr(path, '.');

  if (dot && dot != path) {
    return dot + 1;
  }

  return NULL;
}

static char * eat(char * begin, char * end, char c)
{
  while (*begin == c && begin < end) {
    begin++;
  }

  return begin;
}

static char * copy_range(char * begin, char * end)
{
  size_t length = end - begin;
  char * r = malloc(length + 1);
  strncpy(r, begin, length);
  r[length] = 0;

  return r;
}

static struct accept_type_t * parse_accept_type(char * begin, char * end)
{
  char * type = NULL;
  char * subtype = NULL;
  char * current = eat(begin, end, ' ');

  char * begin_type = current;
  char * end_type = strchr(current, '/');

  if (!end_type) {
    return NULL;
  }

  type = copy_range(begin_type, end_type ? end_type : end);

  current = end_type + 1;

  char * begin_subtype = current;
  char * end_subtype = strpbrk(current, ";, ");
  subtype = copy_range(begin_subtype, end_subtype ? end_subtype : end);

  struct accept_type_t * t = malloc(sizeof(struct accept_type_t));
  t->type = type;
  t->subtype = subtype;
  return t;
}

static struct content_type_t * content_type_for_path(
    struct file_server_t * fs, char * path, char * accept_header)
{
  multimap_t * type_map = fs->type_map;
  char * extension = file_extension(path);

  log_append(fs->log, LOG_DEBUG, "Got extension: %s", extension);

  struct accept_type_t * head = NULL;

  if (accept_header) {
    size_t offset = 0;
    size_t length = strlen(accept_header);

    do {
      char * end = strchr(accept_header + offset, ',');

      if (!end) {
        end = accept_header + length;
      }

      struct accept_type_t * new_type = parse_accept_type(accept_header + offset, end);

      if (!new_type) {
        break;
      }

      log_append(fs->log, LOG_DEBUG, "Accept Type: %s/%s", new_type->type, new_type->subtype);
      new_type->next = head;
      head = new_type;

      offset = end - accept_header + 1;
    } while (offset < length);
  }

  struct content_type_t * match = NULL;

  if (extension) {
    multimap_values_t * types_for_extension = multimap_get(type_map, extension);

    if (types_for_extension && head) {
      // find the first matching content type
      struct accept_type_t * current_accept_type = head;

      while (!match && current_accept_type) {

        if (strcmp(current_accept_type->type, "*") == 0) {
          match = types_for_extension->value;
          break;
        }

        multimap_values_t * content_types = types_for_extension;

        while (content_types) {
          struct content_type_t * current_content_type = content_types->value;

          if (strcmp(current_content_type->type, current_accept_type->type) == 0) {
            if (strcmp(current_accept_type->subtype, "*") == 0 ||
                strcmp(current_content_type->subtype, current_accept_type->subtype) == 0) {

              match = current_content_type;
              break;
            }
          }

          content_types = content_types->next;
        }

        current_accept_type = current_accept_type->next;
      }
    } else if (types_for_extension) {
      match = types_for_extension->value;
    }
  } else {
    // no extension?
    struct content_type_t * content_type = fs->default_content_type;
    struct accept_type_t * current_accept_type = head;

    while (!match && current_accept_type) {

      if (strcmp(current_accept_type->type, "*") == 0) {
        match = content_type;
        break;
      }

      if (strcmp(content_type->type, current_accept_type->type) == 0) {
        if (strcmp(current_accept_type->subtype, "*") == 0 ||
            strcmp(content_type->subtype, current_accept_type->subtype) == 0) {

          match = content_type;
          break;
        }
      }

      current_accept_type = current_accept_type->next;
    }
  }

  // go through and free
  struct accept_type_t * current = head;

  while (current) {
    struct accept_type_t * next = current->next;
    free(current->type);
    free(current->subtype);
    free(current);

    current = next;
  }

  return match;
}

static void file_server_uv_stat_cb(uv_fs_t * req)
{
  struct file_server_request_t * fs_request = req->data;
  http_response_t * response = fs_request->response;
  struct file_server_t * fs = fs_request->file_server;

  if (req->result != 0) {
    log_append(fs->log, LOG_ERROR, "Could not stat file: %d: %s", req->result, fs_request->path);
    http_response_write_error(response, 500);
    file_server_finish_request(fs_request);
  } else if (!S_ISREG(req->statbuf.st_mode)) {
    log_append(fs->log, LOG_ERROR, "Not a regular file: %d, %s", req->result, fs_request->path);
    abort();
    http_response_write_error(response, 404);
    file_server_finish_request(fs_request);
  } else {
    fs_request->content_length = req->statbuf.st_size;
    fs_request->bytes_read = 0;

    char * path = fs_request->path;

    http_response_status_set(response, 200);

    char * accept_header = http_request_header_get(fs_request->response->request, "accept");
    log_append(fs->log, LOG_DEBUG, "Accept header: %s", accept_header);
    struct content_type_t * content_type = content_type_for_path(fs, path, accept_header);

    if (content_type) {
      char content_type_s[strlen(content_type->type) + strlen(content_type->subtype) + 2];
      sprintf(content_type_s, "%s/%s", content_type->type, content_type->subtype);
      http_response_header_add(response, "content-type", content_type_s);
    }

    // content length header
    char content_length_s[256];
    snprintf(content_length_s, 255, "%zu", fs_request->content_length);
    http_response_header_add(response, "content-length", content_length_s);

    // last modified header
    time_t last_modified = req->statbuf.st_mtime;

    if (last_modified >= 0) {
      size_t last_modified_buf_length = RFC1123_TIME_LEN + 1;
      char last_modified_buf[last_modified_buf_length];
      char * last_modified_s = date_rfc1123(last_modified_buf, last_modified_buf_length, last_modified);
      http_response_header_add(response, "last-modified", last_modified_s);
    }

    http_response_header_add(response, "server", PACKAGE_STRING);

    size_t date_buf_length = RFC1123_TIME_LEN + 1;
    char date_buf[date_buf_length];
    char * date = current_date_rfc1123(date_buf, date_buf_length);

    if (date) {
      http_response_header_add(response, "date", date);
    }

    http_response_write(response, NULL, 0, false);

    uv_buf_t * buf = &fs_request->buf;
    buf->len = fs_request->content_length > READ_BUF_SIZE ? READ_BUF_SIZE : fs_request->content_length;
    buf->base = malloc(buf->len);

    file_server_read_file(fs_request, -1);
  }

  uv_fs_req_cleanup(req);
}

static void file_server_uv_open_cb(uv_fs_t * req)
{
  struct file_server_request_t * fs_request = req->data;
  struct file_server_t * fs = fs_request->file_server;

  if (req->result != -1) {

    fs_request->fd = req->result;

    if (uv_fs_fstat(fs_request->loop, &fs_request->stat_req, fs_request->fd, file_server_uv_stat_cb)) {
      http_response_write_error(fs_request->response, 500);
      file_server_finish_request(fs_request);
    }

  } else {
    log_append(fs->log, LOG_ERROR, "Could not open file: %s", fs_request->path);
    http_response_write_error(fs_request->response, 404);
    file_server_finish_request(fs_request);
  }

  uv_fs_req_cleanup(req);
}

static void files_plugin_request_handler(struct plugin_t * plugin, struct client_t * client, http_request_t * request,
    http_response_t * response)
{
  struct file_server_t * file_server = plugin->data;
  struct file_server_request_t * fs_request = malloc(sizeof(file_server_request_t));
  fs_request->response = response;
  struct worker_t * worker = client->worker;
  fs_request->loop = &worker->loop;
  fs_request->file_server = file_server;
  fs_request->stat_req.data = fs_request;
  fs_request->open_req.data = fs_request;
  fs_request->read_req.data = fs_request;
  fs_request->close_req.data = fs_request;
  fs_request->path = NULL;
  fs_request->fd = -1;
  fs_request->buf.base = NULL;
  fs_request->buf.len = 0;

  request->data = fs_request;

  char * method = http_request_method(request);

  if (strcmp(method, "GET") != 0) {
    log_append(file_server->log, LOG_ERROR, "No path provided");
    http_response_header_add(response, "allow", "GET");
    http_response_write_error(response, 405); // method not allowed
    file_server_finish_request(fs_request);
    return;
  }

  char * input_path = http_request_path(request);

  if (!input_path) {
    log_append(file_server->log, LOG_ERROR, "No path provided");
    http_response_write_error(response, 500);
    file_server_finish_request(fs_request);
    return;
  }

  size_t relative_input_path_length = strlen(input_path) + 2 + 1;
  char relative_input_path[relative_input_path_length];
  snprintf(relative_input_path, relative_input_path_length, "./%s", input_path);
  char * path = malloc(PATH_MAX);

  if (!realpath(relative_input_path, path)) {
    log_append(file_server->log, LOG_ERROR, "Could not get path: %s", input_path);
    http_response_write_error(response, 404);
    file_server_finish_request(fs_request);
    free(path);
    return;
  }

  log_append(file_server->log, LOG_DEBUG, "Requested file: %s", path);
  fs_request->path = path;

  size_t path_length = strlen(path);

  // check to make sure the file is in the current directory
  if (path_length < file_server->cwd_length || memcmp(file_server->cwd, path, file_server->cwd_length) != 0) {
    log_append(file_server->log, LOG_ERROR, "%s (%zu) not in %s (%zu)", path, path_length, file_server->cwd,
               file_server->cwd_length);
    http_response_write_error(response, 404);
    file_server_finish_request(fs_request);
    return;
  }

  uv_fs_open(fs_request->loop, &fs_request->open_req, fs_request->path, O_RDONLY, 0644, file_server_uv_open_cb);
}

static void files_plugin_data_handler(struct plugin_t * plugin, struct client_t * client, http_request_t * request,
                                      http_response_t * response,
                                      uint8_t * buf, size_t length, bool last, bool free_buf)
{
  UNUSED(plugin);
  UNUSED(client);
  UNUSED(request);
  UNUSED(response);
  UNUSED(length);
  UNUSED(last);

  if (free_buf) {
    free(buf);
  }

}

static bool files_plugin_handler(struct plugin_t * plugin, struct client_t * client, enum plugin_callback_e cb, va_list args)
{
  switch (cb) {
    case HANDLE_REQUEST:
      {
        http_request_t * request = va_arg(args, http_request_t *);
        http_response_t * response = va_arg(args, http_response_t *);
        files_plugin_request_handler(plugin, client, request, response);
        return true;
      }

    case HANDLE_DATA:
      {
        http_request_t * request = va_arg(args, http_request_t *);
        http_response_t * response = va_arg(args, http_response_t *);
        uint8_t * buf = va_arg(args, uint8_t *);
        size_t length = va_arg(args, size_t);
        bool last = (bool) va_arg(args, int);
        bool free_buf = (bool) va_arg(args, int);
        files_plugin_data_handler(plugin, client, request, response, buf, length, last, free_buf);
        return true;
      }

    default:
      return false;
  }
}

void plugin_initialize(struct plugin_t * plugin, struct worker_t * worker)
{
  plugin->handlers->start = files_plugin_start;
  plugin->handlers->stop = files_plugin_stop;
  plugin->handlers->handle = files_plugin_handler;

  struct file_server_t * file_server = malloc(sizeof(struct file_server_t));
  file_server->log = &worker->config->plugin_log;

  plugin->data = file_server;

  file_server->plugin = plugin;
  file_server->worker = worker;

  files_plugin_init_type_map(file_server);
}

