#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include "util/util.h"
#include "tls.h"

#define TLS_BUF_LENGTH 0x4000

// list of suported protocols
// TLS 'wire' format: length prefixed, non-empty 8-bit characters
const unsigned char supported_protocols[] = { 5, 'h', '2', '-', '1', '2' };
const unsigned char supported_protocols_length = 6;

bool tls_init()
{
  SSL_library_init();
  SSL_load_error_strings();

  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();

  return true;
}

static bool tls_wants_read(const SSL * const ssl, int retval)
{
  int err = SSL_get_error(ssl, retval);

  switch (err) {
    case SSL_ERROR_WANT_READ:
      return true;
  }

  return false;
}

static bool tls_wants_write(const SSL * const ssl, int retval)
{
  int err = SSL_get_error(ssl, retval);

  switch (err) {
    case SSL_ERROR_WANT_WRITE:
      return true;
  }

  return false;
}

static bool tls_debug_error(const SSL * const ssl, int retval, char * prefix)
{
  int err = SSL_get_error(ssl, retval);

  switch (err) {
    case SSL_ERROR_WANT_READ:
      log_trace("%s: WANT_READ", prefix);
      break; // not an error condition

    case SSL_ERROR_WANT_WRITE:
      log_trace("%s: WANT_WRITE", prefix);
      break; // not an error condition

    case SSL_ERROR_NONE:
      log_error("%s: SSL_ERROR_NONE", prefix);
      return false;

    case SSL_ERROR_ZERO_RETURN:
      log_error("%s: SSL_ERROR_ZERO_RETURN", prefix);
      return false;

    case SSL_ERROR_WANT_CONNECT:
      log_error("%s: WANT_CONNECT", prefix);

    case SSL_ERROR_WANT_ACCEPT:
      log_error("%s: WANT_ACCEPT", prefix);
      return false;

    case SSL_ERROR_WANT_X509_LOOKUP:
      log_error("%s: WANT_X509_LOOKUP", prefix);
      return false;

    case SSL_ERROR_SYSCALL:
      err = ERR_get_error();
      log_error("%s: ERROR_SYSCALL: %d", prefix, err);
      return false;

    case SSL_ERROR_SSL:
      err = ERR_get_error();
      log_error("%s: Generic ERROR: %d", prefix, err);
      return false;
  }

  return true;
}

// handles NPN negotiation
static int next_proto_cb(SSL * ssl, const unsigned char ** data, unsigned int * len, void * arg)
{
  UNUSED(ssl);
  UNUSED(arg);

  log_trace("Selecting protocol [NPN]");
  *data = supported_protocols;
  *len = supported_protocols_length;

  return SSL_TLSEXT_ERR_OK;
}

// handles ALPN negotiation
static int alpn_cb(SSL * ssl, const unsigned char ** out, unsigned char * outlen, const unsigned char * in,
                   unsigned int inlen, void * arg)
{
  UNUSED(ssl);
  UNUSED(arg);

  log_trace("Selecting protocol [ALPN]");

  if (SSL_select_next_proto((unsigned char **) out, outlen, supported_protocols, supported_protocols_length, in,
                            inlen) != OPENSSL_NPN_NEGOTIATED) {
    return SSL_TLSEXT_ERR_NOACK;
  }

  return SSL_TLSEXT_ERR_OK;
}

tls_server_ctx_t * tls_server_init()
{
  SSL_CTX * ssl_ctx = SSL_CTX_new(TLSv1_2_server_method());

  SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1);
  SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);

  // set certificates
  SSL_CTX_use_certificate_file(ssl_ctx, "cert.pem", SSL_FILETYPE_PEM);
  SSL_CTX_use_PrivateKey_file(ssl_ctx, "key.pem", SSL_FILETYPE_PEM);

  // set up protocol negotiation callbacks
  SSL_CTX_set_next_protos_advertised_cb(ssl_ctx, next_proto_cb, NULL);
  SSL_CTX_set_alpn_select_cb(ssl_ctx, alpn_cb, NULL);

  tls_server_ctx_t * tls_server_ctx = malloc(sizeof(tls_server_ctx_t));
  tls_server_ctx->ssl_ctx = ssl_ctx;

  return tls_server_ctx;
}

bool tls_server_free(tls_server_ctx_t * server_ctx)
{

  SSL_CTX_free(server_ctx->ssl_ctx);
  free(server_ctx);

  return true;
}

tls_client_ctx_t * tls_client_init(tls_server_ctx_t * server_ctx, void * data,
                                   tls_write_to_network_cb write_to_network, tls_write_to_app_cb write_to_app)
{

  tls_client_ctx_t * tls_client_ctx = malloc(sizeof(tls_client_ctx_t));
  ASSERT_OR_RETURN_NULL(tls_client_ctx);
  tls_client_ctx->handshake_complete = false;
  tls_client_ctx->writing_to_app = false;
  tls_client_ctx->data = data;
  tls_client_ctx->write_to_network = write_to_network;
  tls_client_ctx->write_to_app = write_to_app;
  tls_client_ctx->ssl = NULL;
  tls_client_ctx->app_bio = NULL;
  tls_client_ctx->network_bio = NULL;

  SSL * ssl = SSL_new(server_ctx->ssl_ctx);

  if (!ssl) {
    tls_client_free(tls_client_ctx);
    return NULL;
  }

  tls_client_ctx->ssl = ssl;

  // TODO - test with small bio buffer sizes
  int err = BIO_new_bio_pair(&tls_client_ctx->app_bio, 0, &tls_client_ctx->network_bio, 0); // 0 for default size

  if (err != 1) {
    log_error("Unable to create BIO pair");
    tls_client_free(tls_client_ctx);
    return NULL;
  }

  SSL_set_bio(ssl, tls_client_ctx->app_bio, tls_client_ctx->app_bio); // "cannot fail"

  SSL_set_accept_state(tls_client_ctx->ssl); // no return

  return tls_client_ctx;

}

static bool tls_read_decrypted_data_and_pass_to_app(tls_client_ctx_t * client_ctx)
{
  if (client_ctx->writing_to_app) {
    // we're already in the process of writing to the app -
    // don't do again it until we're finished
    return true;
  }

  log_trace("Reading decrypted data from app BIO and passing to app");

  do {
    // read decrypted data
    uint8_t * read_buf = malloc(sizeof(uint8_t) * TLS_BUF_LENGTH);
    int retval = SSL_read(client_ctx->ssl, read_buf, TLS_BUF_LENGTH);

    if (retval > 0) {
      log_trace("SSL_read returned %ld", retval);

      client_ctx->writing_to_app = true;

      if (!client_ctx->write_to_app(client_ctx->data, read_buf, retval)) {
        log_error("Could not write decrypted data to application");
        return false;
      }

      client_ctx->writing_to_app = false;
    } else if (tls_wants_read(client_ctx->ssl, retval)) {
      log_trace("SSL_read: wants read");
      free(read_buf);
      break; // continue
    } else if (tls_wants_write(client_ctx->ssl, retval)) {
      log_trace("SSL_read: wants write");
      free(read_buf);
      break; // continue
    } else {
      free(read_buf);
      tls_debug_error(client_ctx->ssl, retval, "SSL_read");
      return false;
    }

  } while (true);

  return true;

}

static bool tls_read_encrypted_data_and_pass_to_network(tls_client_ctx_t * client_ctx)
{
  do {
    // read encrypted data from network bio, write to socket
    uint8_t * read_buf = malloc(sizeof(uint8_t) * TLS_BUF_LENGTH);
    log_trace("Reading encrypted data from network BIO");
    int retval = BIO_read(client_ctx->network_bio, read_buf, TLS_BUF_LENGTH);

    if (retval > 0) {
      log_trace("BIO read: %d", retval);

      if (!client_ctx->write_to_network(client_ctx->data, read_buf, retval)) {
        return false;
      }

      free(read_buf);

      // try to BIO_read again
    } else if (BIO_should_read(client_ctx->network_bio)) {
      log_trace("Network BIO: should read");
      free(read_buf);
      break; // continue
    } else if (BIO_should_write(client_ctx->network_bio)) {
      log_trace("Network BIO: should write");
      free(read_buf);
      break; // continue
    } else {
      free(read_buf);
      return tls_debug_error(client_ctx->ssl, retval, "Network BIO read failed");
    }
  } while (true);

  return true;
}

static bool tls_update(tls_client_ctx_t * client_ctx)
{

  if (!tls_read_decrypted_data_and_pass_to_app(client_ctx)) {
    return false;
  }

  if (!tls_read_encrypted_data_and_pass_to_network(client_ctx)) {
    return false;
  }

  return true;

}

bool tls_decrypt_data_and_pass_to_app(tls_client_ctx_t * client_ctx, uint8_t * buf, size_t length)
{

  log_trace("Writing encrypted data to network BIO");

  size_t written = 0;

  do {
    int retval = BIO_write(client_ctx->network_bio, buf + written, length - written);

    if (retval > 0) {
      log_trace("Wrote %d/%ld octets of encrypted data to network BIO for decryption", retval, length);
      written += retval;
    } else if (BIO_should_retry(client_ctx->network_bio)) {
      // the network BIO buffer maybe full - try freeing some space by
      // reading from it and passing it on to the app
      if (!tls_read_decrypted_data_and_pass_to_app(client_ctx)) {
        log_error("Could not write encrypted data to network BIO for decryption: %d (should retry)", retval);
        free(buf);

        return false;
      }

      // otherwise try again
    } else {
      // fatal error
      log_error("Could not write encrypted data to network BIO for decryption: %d", retval);
      free(buf);

      return false;
    }
  } while (written < length);

  free(buf);

  if (!client_ctx->handshake_complete) {

    log_trace("Attempting handshake");
    int retval = SSL_do_handshake(client_ctx->ssl);

    if (retval == 1) {
      // success
      client_ctx->handshake_complete = true;
      log_trace("Handshake complete");
    } else if (tls_wants_read(client_ctx->ssl, retval)) {
      log_trace("Handshake not yet complete, should read");
    } else if (tls_wants_write(client_ctx->ssl, retval)) {
      log_trace("Handshake not yet complete, should write");
    } else {
      tls_debug_error(client_ctx->ssl, retval, "Handshake failed");
    }

  }

  return tls_update(client_ctx);
}

bool tls_encrypt_data_and_pass_to_network(tls_client_ctx_t * client_ctx, uint8_t * buf, size_t length)
{

  log_trace("Encrypting %ld octets of data from application", length);

  size_t written = 0;
  size_t remaining_length = length;

  do {
    int retval = SSL_write(client_ctx->ssl, buf + written, length - written);

    if (retval > 0) {
      log_trace("SSL_write returned: %ld", retval);
      written += retval;
    } else if (tls_wants_read(client_ctx->ssl, retval)) {
      log_trace("SSL_write: wants read with %ld bytes remaining", remaining_length);

      // the ssl write buffer may be full, try to clear it out by
      // reading the already encrypted data from it
      if (!tls_read_encrypted_data_and_pass_to_network(client_ctx)) {
        return false;
      }

      // try again
    } else if (tls_wants_write(client_ctx->ssl, retval)) {
      log_warning("SSL_write: wants write with %ld bytes remaining", remaining_length);
      free(buf);
      return false;
    } else {
      tls_debug_error(client_ctx->ssl, retval, "SSL_write");
      return false;
    }
  } while (written < length);

  return tls_update(client_ctx);

}

bool tls_client_free(tls_client_ctx_t * client_ctx)
{
  if (client_ctx->ssl) {
    SSL_free(client_ctx->ssl);
  }

  if (client_ctx->network_bio) {
    BIO_free(client_ctx->network_bio);
  }

  free(client_ctx);

  return true;
}

