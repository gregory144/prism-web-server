#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include "util/util.h"
#include "tls.h"

#define TLS_BUF_LENGTH 0x4000

bool tls_init_static()
{
  SSL_library_init();
  SSL_load_error_strings();

  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();

  return true;
}

#define WHERE_INFO(ssl, w, flag, msg) { \
  if(w & flag) { \
    fprintf(stderr, "\t"); \
    fprintf(stderr, msg); \
    fprintf(stderr, " - %s ", SSL_state_string(ssl)); \
    fprintf(stderr, " - %s ", SSL_state_string_long(ssl)); \
    fprintf(stderr, "\n"); \
  } \
}

static bool tls_wants_read(const SSL * const ssl, int retval) {
  int err = SSL_get_error(ssl, retval);
  switch (err) {
    case SSL_ERROR_WANT_READ:
      return true;
  }

  return false;
}

static bool tls_wants_write(const SSL * const ssl, int retval) {
  int err = SSL_get_error(ssl, retval);
  switch (err) {
    case SSL_ERROR_WANT_WRITE:
      return true;
  }

  return false;
}

static bool tls_debug_error(const SSL * const ssl, int retval, char * prefix) {
  int err = SSL_get_error(ssl, retval);
  switch (err) {
    case SSL_ERROR_NONE:
      log_error("%s: SSL_ERROR_NONE", prefix);
      return NULL;
    case SSL_ERROR_ZERO_RETURN:
      log_error("%s: SSL_ERROR_ZERO_RETURN", prefix);
      return NULL;
    case SSL_ERROR_WANT_READ:
      log_error("%s: WANT_READ", prefix);
      /*return NULL;*/
      break;
    case SSL_ERROR_WANT_WRITE:
      log_error("%s: WANT_WRITE", prefix);
      return NULL;
    case SSL_ERROR_WANT_CONNECT:
      log_error("%s: WANT_CONNECT", prefix);
    case SSL_ERROR_WANT_ACCEPT:
      log_error("%s: WANT_ACCEPT", prefix);
      return NULL;
    case SSL_ERROR_WANT_X509_LOOKUP:
      log_error("%s: WANT_X509_LOOKUP", prefix);
      return NULL;
    case SSL_ERROR_SYSCALL:
      err = ERR_get_error();
      log_error("%s: ERROR_SYSCALL: %d", prefix, err);
      return NULL;
    case SSL_ERROR_SSL:
      log_error("%s: ERROR", prefix);
      err = ERR_get_error();
      log_error("Generic %d", err);
      return NULL;
  }

  return true;
}

static void info_callback(const SSL * ssl, int where, int ret)
{
  if (ret == 0) {
    fprintf(stderr, "info_callback, error occured.\n");
    return;
  }

  WHERE_INFO(ssl, where, SSL_CB_LOOP, "LOOP");
  WHERE_INFO(ssl, where, SSL_CB_EXIT, "EXIT");
  WHERE_INFO(ssl, where, SSL_CB_READ, "READ");
  WHERE_INFO(ssl, where, SSL_CB_WRITE, "WRITE");
  WHERE_INFO(ssl, where, SSL_CB_ALERT, "ALERT");
  WHERE_INFO(ssl, where, SSL_CB_HANDSHAKE_DONE, "HANDSHAKE DONE");
}


static void msg_callback(int writep, int version, int contentType, const void * buf, size_t len, SSL * ssl, void * arg)
{
  UNUSED(writep);
  UNUSED(version);
  UNUSED(contentType);
  UNUSED(buf);
  UNUSED(ssl);
  UNUSED(arg);
  fprintf(stderr, "\tMessage callback with length: %ld\n", len);
}

static int verify_callback(int ok, X509_STORE_CTX * store)
{
  char buf[256];
  int err, depth;
  X509 * err_cert;
  err_cert = X509_STORE_CTX_get_current_cert(store);
  err = X509_STORE_CTX_get_error(store);
  depth = X509_STORE_CTX_get_error_depth(store);
  X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);

  BIO * outbio = BIO_new_fp(stdout, BIO_NOCLOSE);
  X509_NAME * cert_name = X509_get_subject_name(err_cert);
  X509_NAME_print_ex(outbio, cert_name, 0, XN_FLAG_MULTILINE);
  BIO_free_all(outbio);
  fprintf(stderr, "\tverify_callback(), ok: %d, error: %d, depth: %d, name: %s\n", ok, err, depth, buf);

  return 1; // We always return 1, so no verification actually
}

static int next_proto_cb(SSL * ssl, const unsigned char ** data, unsigned int * len, void * arg)
{
  UNUSED(ssl);
  UNUSED(arg);

  // 'wire' format: length prefixed, non-empty 8-bit characters
  unsigned char protos[] = { 5, 'h', '2', '-', '1', '2' };
  *data = protos;
  *len = 6;

  return SSL_TLSEXT_ERR_OK;
}

tls_server_ctx_t * tls_server_init()
{
  SSL_CTX * ssl_ctx = SSL_CTX_new(TLSv1_2_server_method());

  SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1);
  SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, verify_callback);
  SSL_CTX_set_info_callback(ssl_ctx, info_callback);
  SSL_CTX_set_msg_callback(ssl_ctx, msg_callback);

  SSL_CTX_use_certificate_file(ssl_ctx, "cert.pem", SSL_FILETYPE_PEM);
  SSL_CTX_use_PrivateKey_file(ssl_ctx, "key.pem", SSL_FILETYPE_PEM);

  SSL_CTX_set_next_protos_advertised_cb(ssl_ctx, next_proto_cb, NULL);

  tls_server_ctx_t * tls_server_ctx = malloc(sizeof(tls_server_ctx_t));
  tls_server_ctx->ssl_ctx = ssl_ctx;

  return tls_server_ctx;
}

long tls_network_callback(BIO *b, int oper, const char *argp, int argi, long argl, long retvalue) {
  UNUSED(b);
  UNUSED(argp);
  UNUSED(argl);
  /*log_error("network callback: %s", argp);*/
  switch (oper) {
    case BIO_CB_READ | BIO_CB_RETURN:
      log_error("network READ: %d", argi);
      break;
    case BIO_CB_WRITE | BIO_CB_RETURN:
      log_error("network WRITE %d", argi);
      break;
  }
  return retvalue;
}

long tls_app_callback(BIO *b, int oper, const char *argp, int argi, long argl, long retvalue) {
  UNUSED(b);
  UNUSED(argp);
  UNUSED(argl);
  /*log_error("app callback");*/
  switch (oper) {
    case BIO_CB_READ | BIO_CB_RETURN:
      log_error("app READ %d", argi);
      break;
    case BIO_CB_WRITE | BIO_CB_RETURN:
      log_error("app WRITE %d", argi);
      break;
  }
  return retvalue;
}

tls_client_ctx_t * tls_client_init(tls_server_ctx_t * server_ctx, void * data,
    tls_write_to_network_cb write_to_network, tls_read_from_app_cb read_from_app)
{

  tls_client_ctx_t * tls_client_ctx = malloc(sizeof(tls_client_ctx_t));
  tls_client_ctx->handshake_complete = false;
  tls_client_ctx->data = data;
  tls_client_ctx->write_to_network = write_to_network;
  tls_client_ctx->read_from_app = read_from_app;

  SSL * ssl = SSL_new(server_ctx->ssl_ctx);
  ASSERT_OR_RETURN_NULL(ssl);
  tls_client_ctx->ssl = ssl;

  int err = BIO_new_bio_pair(&tls_client_ctx->app_bio, 0, &tls_client_ctx->network_bio, 0); // 0 for default size
  if (err != 1) {
    log_error("Unable to create BIO pair");
  }

  SSL_set_bio(ssl, tls_client_ctx->app_bio, tls_client_ctx->app_bio);

  /*BIO_set_callback(tls_client_ctx->app_bio, tls_app_callback);*/
  /*BIO_set_callback_arg(tls_client_ctx->app_bio, "app");*/

  /*BIO_set_callback(tls_client_ctx->network_bio, tls_network_callback);*/
  /*BIO_set_callback_arg(tls_client_ctx->network_bio, "network");*/

  SSL_set_accept_state(tls_client_ctx->ssl);

  return tls_client_ctx;

}

static bool tls_update(tls_client_ctx_t * client_ctx) {
  // read encrypted data from network bio, write to socket
  uint8_t * read_buf = malloc(sizeof(uint8_t) * TLS_BUF_LENGTH);
  int retval = BIO_read(client_ctx->network_bio, read_buf, TLS_BUF_LENGTH);
  if (retval > 0) {
    return tls_write_to_network(client_ctx, read_buf, retval);
  } else {
    tls_debug_error(client_ctx->ssl, retval, "read from network bio");
    return false;
  }

}

bool tls_read_from_network(tls_client_ctx_t * client_ctx, uint8_t * buf, size_t length) {

  log_error("Reading from network");

  int err = BIO_write(client_ctx->network_bio, buf, length);
  if (err <= 0) {
    log_error("Could not write TLS data: %d", err);
  } else {
    log_error("Wrote %d/%ld octets of TLS data", err, length);
  }

  if (!client_ctx->handshake_complete) {
    err = SSL_do_handshake(client_ctx->ssl);
    if (err <= 0) {
      tls_debug_error(client_ctx->ssl, err, "Handshake failed:");
    } else {
      client_ctx->handshake_complete = true;
      log_error("Handshake complete");
    }
  }

  uint8_t * read_buf = malloc(sizeof(uint8_t) * TLS_BUF_LENGTH);
  int retval;
  if (client_ctx->handshake_complete) {
    // read decrypted data from network bio
    retval = SSL_read(client_ctx->ssl, read_buf, TLS_BUF_LENGTH);
    if (retval > 0) {
        log_error("SSL_read returned %ld", retval);
      if (!tls_write_to_app(client_ctx, read_buf, retval)) {
        log_error("Could not write decrypted data to application");
      }
    } else if (tls_wants_read(client_ctx->ssl, retval)) {
      log_error("SSL_read: Want read");
    } else {
      tls_debug_error(client_ctx->ssl, retval, "SSL_read");
      return false;
    }
  }

  return tls_update(client_ctx);;

  return true;
}

bool tls_write_to_network(tls_client_ctx_t * client_ctx, uint8_t * buf, size_t length) {
  return client_ctx->write_to_network(client_ctx->data, buf, length);
}

bool tls_read_from_app(tls_client_ctx_t * client_ctx, uint8_t * buf, size_t length) {

  int retval = SSL_write(client_ctx->ssl, buf, length);
  if (retval > 0) {
      log_error("SSL_write returned %ld", retval);
    return tls_update(client_ctx);
  } else if (tls_wants_write(client_ctx->ssl, retval)) {
    log_error("SSL_write: Want write");
    return true;
  } else {
    tls_debug_error(client_ctx->ssl, retval, "SSL_write");
    return false;
  }

  /*int err = BIO_write(client_ctx->network_bio, buf, length);*/
  /*if (err <= 0) {*/
    /*log_error("Could not write TLS data: %d", err);*/
    /*return false;*/
  /*} else {*/
    /*log_error("Wrote %d/%ld octets of TLS data", err, length);*/
  /*}*/

  /*uint8_t * read_buf = malloc(sizeof(uint8_t) * TLS_BUF_LENGTH);*/
  /*size_t read = BIO_read(client_ctx->app_bio, read_buf, TLS_BUF_LENGTH);*/
  /*return tls_write_to_app(client_ctx, read_buf, read);*/
}

bool tls_write_to_app(tls_client_ctx_t * client_ctx, uint8_t * buf, size_t length) {
  return client_ctx->read_from_app(client_ctx->data, buf, length);
}

bool tls_free()
{
  return true;
}

