#ifndef HTTP_TLS_H
#define HTTP_TLS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>

typedef bool (*tls_write_to_network_cb)(void * data, uint8_t * buf, size_t length);
typedef bool (*tls_read_from_app_cb)(void * data, uint8_t * buf, size_t length);

typedef struct {
  SSL_CTX * ssl_ctx;
} tls_server_ctx_t;

typedef struct {

  void * data;

  SSL * ssl;
  BIO * app_bio;
  BIO * network_bio;

  bool handshake_complete;

  tls_write_to_network_cb write_to_network;
  tls_read_from_app_cb read_from_app;
} tls_client_ctx_t;

bool tls_init_static();

tls_server_ctx_t * tls_server_init();

tls_client_ctx_t * tls_client_init(tls_server_ctx_t * server_ctx, void * data,
    tls_write_to_network_cb write_to_network, tls_read_from_app_cb read_from_app);

bool tls_read_from_network(tls_client_ctx_t * client_ctx, uint8_t * buf, size_t length);
bool tls_write_to_network(tls_client_ctx_t * client_ctx, uint8_t * buf, size_t length);

bool tls_read_from_app(tls_client_ctx_t * client_ctx, uint8_t * buf, size_t length);
bool tls_write_to_app(tls_client_ctx_t * client_ctx, uint8_t * buf, size_t length);

bool tls_free();

#endif
