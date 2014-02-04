/**
 *
 * Implements HPACK HTTP2 header encoding/decoding. See
 *
 * http://tools.ietf.org/html/draft-ietf-httpbis-header-compression-05
 */

#ifndef HPACK_H
#define HPACK_H 

/**
 * Frame types
 */
/*
#define FRAME_TYPE_DATA 0
#define FRAME_TYPE_HEADERS 1
#define FRAME_TYPE_PRIORITY 2
#define FRAME_TYPE_RST_STREAM 3
#define FRAME_TYPE_SETTINGS 4
#define FRAME_TYPE_PUSH_PROMISE 5
#define FRAME_TYPE_PING 6
#define FRAME_TYPE_GOAWAY 7
#define FRAME_TYPE_WINDOW_UPDATE 8
#define FRAME_TYPE_CONTINUATION 9

typedef struct http_frame_payload_s http_frame_payload_t;
struct http_frame_payload_s {

  char* data;

};

http_parser_t* http_parser_init(void* data, write_cb writer, close_cb closer);

void http_parser_free(http_parser_t* parser);

void http_parser_read(http_parser_t* parser, char* buffer, size_t len);
*/

int hpack_add(int a, int b);

#endif
