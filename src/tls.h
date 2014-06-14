#ifndef HTTP_TLS_H
#define HTTP_TLS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>

/**
 * Here is the basic flow:
 *
 * Lib UV reads data from the socket.
 * That encrypted data is sent to the network BIO.
 * We perform SSL_read to get decrypted data and send it to the application.
 * The application requests a write operation.
 * That decrypted data is sent to SSL_write.
 * We read the encrypted data from the network BIO.
 * We send that encrypted data back to LibUV to write it to the socket.
 */


typedef bool (*tls_write_to_network_cb)(void * data, uint8_t * buf, size_t length);
typedef bool (*tls_write_to_app_cb)(void * data, uint8_t * buf, size_t length);

typedef struct {

  SSL_CTX * ssl_ctx;

} tls_server_ctx_t;

typedef struct {

  void * data;

  SSL * ssl;
  BIO * app_bio;
  BIO * network_bio;

  bool handshake_complete;
  bool writing_to_app;

  tls_write_to_network_cb write_to_network;
  tls_write_to_app_cb write_to_app;

} tls_client_ctx_t;

bool tls_init();

tls_server_ctx_t * tls_server_init(char * key_file, char * cert_file);

bool tls_server_free(tls_server_ctx_t * server_ctx);

tls_client_ctx_t * tls_client_init(tls_server_ctx_t * server_ctx, void * data,
                                   tls_write_to_network_cb write_to_network, tls_write_to_app_cb write_to_app);

/**
 * Called when data has been read from the network and the caller wants to decrypt
 * that data and pass it on to the application
 */
bool tls_decrypt_data_and_pass_to_app(tls_client_ctx_t * client_ctx, uint8_t * buf, size_t length);

/**
 * Called when data has been read from the application
 */
bool tls_encrypt_data_and_pass_to_network(tls_client_ctx_t * client_ctx, uint8_t * buf, size_t length);

bool tls_client_free(tls_client_ctx_t * client_ctx);

#endif
