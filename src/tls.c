#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <uv.h>

#include "util/util.h"
#include "util/hash_table.h"
#include "tls.h"

#define TLS_BUF_LENGTH 0x4000

SSL_CTX * global_ssl_ctx;

static const char * const DEFAULT_CIPHERS =
  "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128:AES256:AES:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK";

static const char * http2_protocol_version_string;
static int http2_protocol_version_string_length;
static const char * http1_1_protocol_version_string;
static int http1_1_protocol_version_string_length;

// list of suported protocols
static unsigned char * supported_protocols;
unsigned char supported_protocols_length;

static int ssl_ctx_app_data_index;

static void tls_prepare_supported_protocols(const char * h2_string, const char * h1_1_string)
{
  http2_protocol_version_string = h2_string;
  http2_protocol_version_string_length = strlen(h2_string);
  http1_1_protocol_version_string = h1_1_string;
  http1_1_protocol_version_string_length = strlen(h1_1_string);

  supported_protocols_length = http2_protocol_version_string_length +
    http1_1_protocol_version_string_length + 2;

  // TLS 'wire' format: length prefixed, non-empty 8-bit characters
  supported_protocols = malloc(supported_protocols_length);
  char * i = supported_protocols;

  i[0] = http2_protocol_version_string_length;
  i++;
  memcpy(i, http2_protocol_version_string, http2_protocol_version_string_length);
  i += http2_protocol_version_string_length;
  i[0] = http1_1_protocol_version_string_length;
  i++;
  memcpy(i, http1_1_protocol_version_string, http1_1_protocol_version_string_length);
}

bool tls_init(const char * h2_protocol_version_string)
{
  SSL_library_init();
  SSL_load_error_strings();

  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();

  ssl_ctx_app_data_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);

  tls_prepare_supported_protocols(h2_protocol_version_string, "http/1.1");

  return true;
}

static bool tls_ssl_wants_read(const SSL * const ssl, int retval)
{
  int err = SSL_get_error(ssl, retval);

  switch (err) {
    case SSL_ERROR_WANT_READ:
      return true;
  }

  return false;
}

static bool tls_ssl_wants_write(const SSL * const ssl, int retval)
{
  int err = SSL_get_error(ssl, retval);

  switch (err) {
    case SSL_ERROR_WANT_WRITE:
      return true;
  }

  return false;
}

static bool tls_ssl_zero_return(const SSL * const ssl, int retval)
{
  int err = SSL_get_error(ssl, retval);

  switch (err) {
    case SSL_ERROR_ZERO_RETURN:
      return true;
  }

  return false;
}

static bool tls_debug_error(const SSL * const ssl, int retval, char * prefix)
{
  tls_server_ctx_t * tls_ctx = (tls_server_ctx_t *) SSL_get_ex_data(ssl, ssl_ctx_app_data_index);

  int err = SSL_get_error(ssl, retval);

  switch (err) {
    case SSL_ERROR_WANT_READ:
      log_append(tls_ctx->log, LOG_TRACE, "%s: WANT_READ", prefix);
      break; // not an error condition

    case SSL_ERROR_WANT_WRITE:
      log_append(tls_ctx->log, LOG_TRACE, "%s: WANT_WRITE", prefix);
      break; // not an error condition

    case SSL_ERROR_NONE:
      log_append(tls_ctx->log, LOG_ERROR, "%s: SSL_ERROR_NONE", prefix);
      return false;

    case SSL_ERROR_ZERO_RETURN:
      log_append(tls_ctx->log, LOG_ERROR, "%s: SSL_ERROR_ZERO_RETURN", prefix);
      return false;

    case SSL_ERROR_WANT_CONNECT:
      log_append(tls_ctx->log, LOG_ERROR, "%s: WANT_CONNECT", prefix);
      return false;

    case SSL_ERROR_WANT_ACCEPT:
      log_append(tls_ctx->log, LOG_ERROR, "%s: WANT_ACCEPT", prefix);
      return false;

    case SSL_ERROR_WANT_X509_LOOKUP:
      log_append(tls_ctx->log, LOG_ERROR, "%s: WANT_X509_LOOKUP", prefix);
      return false;

    case SSL_ERROR_SYSCALL:
      err = ERR_get_error();
      log_append(tls_ctx->log, LOG_ERROR, "%s: ERROR_SYSCALL: %s", prefix, ERR_error_string(err, NULL));
      return false;

    case SSL_ERROR_SSL:
      err = ERR_get_error();
      log_append(tls_ctx->log, LOG_ERROR, "%s: Generic ERROR: %s", prefix, ERR_error_string(err, NULL));
      return false;
  }

  return true;
}

int servername_callback(SSL * ssl, int * al, void * arg)
{
  UNUSED(al);
  UNUSED(arg);

  tls_server_ctx_t * tls_ctx = SSL_get_ex_data(ssl, ssl_ctx_app_data_index);

  const char * hostname = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

  if (hostname) {
    log_append(tls_ctx->log, LOG_TRACE, "SNI hostname: %s", hostname);

    if (!global_ssl_ctx) {
      log_append(tls_ctx->log, LOG_TRACE, "Could not set SSL CTX");
    }

    SSL_set_SSL_CTX(ssl, global_ssl_ctx);
  } else {
    log_append(tls_ctx->log, LOG_TRACE, "SNI hostname: null");
  }

  return SSL_TLSEXT_ERR_OK;
}

// handles NPN negotiation
static int next_proto_callback(SSL * ssl, const unsigned char ** data, unsigned int * len, void * arg)
{
  UNUSED(arg);

  tls_server_ctx_t * tls_ctx = SSL_get_ex_data(ssl, ssl_ctx_app_data_index);

  log_append(tls_ctx->log, LOG_TRACE, "Selecting protocol [NPN]");
  *data = supported_protocols;
  *len = supported_protocols_length;

  return SSL_TLSEXT_ERR_OK;
}

#ifdef HAVE_ALPN

// handles ALPN negotiation
static int alpn_callback(SSL * ssl, const unsigned char ** out, unsigned char * outlen, const unsigned char * in,
                         unsigned int inlen, void * arg)
{
  UNUSED(arg);

  tls_server_ctx_t * tls_ctx = SSL_get_ex_data(ssl, ssl_ctx_app_data_index);

  log_append(tls_ctx->log, LOG_TRACE, "Selecting protocol using ALPN");

  if (SSL_select_next_proto((unsigned char **) out, outlen, supported_protocols, supported_protocols_length, in,
                            inlen) != OPENSSL_NPN_NEGOTIATED) {
    return SSL_TLSEXT_ERR_NOACK;
  }

  return SSL_TLSEXT_ERR_OK;
}

#endif

#define OPENSSL_THREAD_DEFINES
#include <openssl/opensslconf.h>
#if defined(OPENSSL_THREADS)

// openssl thread support enabled

static uv_mutex_t * lock_cs = NULL;

static void tls_locking_cb(int mode, int type, char * file, int line)
{
  UNUSED(file);
  UNUSED(line);

  if (mode & CRYPTO_LOCK) {
    uv_mutex_lock(&(lock_cs[type]));
  } else {
    uv_mutex_unlock(&(lock_cs[type]));
  }
}

static unsigned long tls_thread_id_cb(void)
{
  return uv_thread_self();
}

static void tls_thread_setup(void)
{
  lock_cs = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(uv_mutex_t));

  for (int i = 0; i < CRYPTO_num_locks(); i++) {
    uv_mutex_init(&(lock_cs[i]));
  }

  CRYPTO_set_id_callback((unsigned long( *)())tls_thread_id_cb);
  CRYPTO_set_locking_callback((void ( *)())tls_locking_cb);
}

static void tls_thread_cleanup(void)
{
  if (!lock_cs) {
    return;
  }
  CRYPTO_set_locking_callback(NULL);

  for (int i = 0; i < CRYPTO_num_locks(); i++) {
    uv_mutex_destroy(&(lock_cs[i]));
  }

  OPENSSL_free(lock_cs);
}

#else


static void tls_thread_setup(void)
{
  // noop
}

static void tls_thread_cleanup(void)
{
  // noop
}

#endif

tls_server_ctx_t * tls_server_init(log_context_t * log, char * key_file, char * cert_file)
{
  SSL_CTX * ssl_ctx = SSL_CTX_new(SSLv23_server_method());

  global_ssl_ctx = ssl_ctx;

  SSL_CTX_set_options(ssl_ctx,
                      SSL_OP_NO_SSLv2 |
                      SSL_OP_ALL |
                      SSL_OP_NO_COMPRESSION |
                      SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION |
                      SSL_OP_SINGLE_ECDH_USE |
                      SSL_OP_SINGLE_DH_USE |
                      SSL_OP_NO_TICKET |
                      SSL_OP_CIPHER_SERVER_PREFERENCE
                     );

  SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);

  if (SSL_CTX_set_cipher_list(ssl_ctx, DEFAULT_CIPHERS) == 0) {
    log_append(log, LOG_FATAL, "SSL_CTX_set_cipher_list failed: %s", ERR_error_string(ERR_get_error(), NULL));
    SSL_CTX_free(ssl_ctx);
    return NULL;
  }

  SSL_CTX_set_mode(ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
  SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
  SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);

  // set up elliptic curve key
  EC_KEY * ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

  if (ecdh == NULL) {
    log_append(log, LOG_FATAL, "EC_KEY_new_by_curve_name failed: %s", ERR_error_string(ERR_get_error(), NULL));
    return NULL;
  }

  SSL_CTX_set_tmp_ecdh(ssl_ctx, ecdh);
  EC_KEY_free(ecdh);

  // set up Server Name Indication (SNI) callback
  SSL_CTX_set_tlsext_servername_callback(ssl_ctx, servername_callback);

  // set up Next Protocol Negotiation (NPN) callbacks
  SSL_CTX_set_next_protos_advertised_cb(ssl_ctx, next_proto_callback, NULL);

#ifdef HAVE_ALPN
  // set up Application Layer Protocol Negotiation (ALPN)
  SSL_CTX_set_alpn_select_cb(ssl_ctx, alpn_callback, NULL);
#endif

  // set certificates
  if (SSL_CTX_use_certificate_file(ssl_ctx, cert_file, SSL_FILETYPE_PEM) != 1) {
    log_append(log, LOG_FATAL, "Failed setting certificate file: %s, error: %s",
        cert_file, ERR_error_string(ERR_get_error(), NULL));
    return NULL;
  }
  if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key_file, SSL_FILETYPE_PEM) != 1) {
    log_append(log, LOG_FATAL, "Failed setting private key file: %s, error: %s",
        key_file, ERR_error_string(ERR_get_error(), NULL));
    return NULL;
  }

  tls_thread_setup();

  tls_server_ctx_t * tls_server_ctx = malloc(sizeof(tls_server_ctx_t));
  tls_server_ctx->ssl_ctx = ssl_ctx;
  tls_server_ctx->log = log;

  return tls_server_ctx;
}

bool tls_server_free(tls_server_ctx_t * server_ctx)
{
  tls_thread_cleanup();

  if (server_ctx->ssl_ctx) {
    SSL_CTX_free(server_ctx->ssl_ctx);
    free(server_ctx);
  }

  return true;
}

tls_client_ctx_t * tls_client_init(tls_server_ctx_t * server_ctx, void * data,
                                   tls_write_to_network_cb write_to_network, tls_write_to_app_cb write_to_app)
{

  tls_client_ctx_t * tls_client_ctx = malloc(sizeof(tls_client_ctx_t));
  ASSERT_OR_RETURN_NULL(tls_client_ctx);
  tls_client_ctx->log = server_ctx->log;
  tls_client_ctx->selected_protocol = NULL;
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

  SSL_set_ex_data(ssl, ssl_ctx_app_data_index, server_ctx);

  tls_client_ctx->ssl = ssl;

  // TODO - test with small bio buffer sizes
  int err = BIO_new_bio_pair(&tls_client_ctx->app_bio, 0, &tls_client_ctx->network_bio, 0); // 0 for default size

  if (err != 1) {
    log_append(server_ctx->log, LOG_ERROR, "Unable to create BIO pair");
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
    // don't do it again until we're finished
    return true;
  }

  log_append(client_ctx->log, LOG_TRACE, "Reading decrypted data from app BIO and passing to app");

  while (true) {
    // read decrypted data
    uint8_t * read_buf = malloc(sizeof(uint8_t) * TLS_BUF_LENGTH);
    int retval = SSL_read(client_ctx->ssl, read_buf, TLS_BUF_LENGTH);

    if (retval > 0) {
      log_append(client_ctx->log, LOG_TRACE, "SSL_read returned %d", retval);

      client_ctx->writing_to_app = true;

      if (!client_ctx->write_to_app(client_ctx->data, read_buf, retval)) {
        log_append(client_ctx->log, LOG_ERROR, "Could not write decrypted data to application");
        return false;
      }

      client_ctx->writing_to_app = false;
    } else if (tls_ssl_wants_read(client_ctx->ssl, retval)) {
      log_append(client_ctx->log, LOG_TRACE, "SSL_read: wants read");
      free(read_buf);
      break; // continue
    } else if (tls_ssl_wants_write(client_ctx->ssl, retval)) {
      log_append(client_ctx->log, LOG_TRACE, "SSL_read: wants write");
      free(read_buf);
      break; // continue
    } else if (tls_ssl_zero_return(client_ctx->ssl, retval)) {
      log_append(client_ctx->log, LOG_TRACE, "SSL_read: eof");
      free(read_buf);
      break; // continue
    } else {
      free(read_buf);
      tls_debug_error(client_ctx->ssl, retval, "SSL_read");
      return false;
    }

  }

  return true;

}

static bool tls_read_encrypted_data_and_pass_to_network(tls_client_ctx_t * client_ctx)
{
  do {
    // read encrypted data from network bio, write to socket
    uint8_t * read_buf = malloc(sizeof(uint8_t) * TLS_BUF_LENGTH);
    log_append(client_ctx->log, LOG_TRACE, "Reading encrypted data from network BIO");
    int retval = BIO_read(client_ctx->network_bio, read_buf, TLS_BUF_LENGTH);

    if (retval > 0) {
      log_append(client_ctx->log, LOG_TRACE, "BIO read: %d", retval);

      if (!client_ctx->write_to_network(client_ctx->data, read_buf, retval)) {
        return false;
      }

      free(read_buf);

      // try to BIO_read again
    } else if (BIO_should_read(client_ctx->network_bio)) {
      log_append(client_ctx->log, LOG_TRACE, "Network BIO: should read");
      free(read_buf);
      break; // continue
    } else if (BIO_should_write(client_ctx->network_bio)) {
      log_append(client_ctx->log, LOG_TRACE, "Network BIO: should write");
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

bool tls_set_version(tls_client_ctx_t * client_ctx)
{
  client_ctx->selected_tls_version = SSL_get_version(client_ctx->ssl);
  client_ctx->selected_cipher = SSL_get_cipher_name(client_ctx->ssl);
  client_ctx->cipher_key_size_in_bits = SSL_get_cipher_bits(client_ctx->ssl, NULL);

  log_append(client_ctx->log, LOG_DEBUG, "SSL version: %s", client_ctx->selected_tls_version);
  log_append(client_ctx->log, LOG_DEBUG, "SSL cipher: %s, %d", client_ctx->selected_cipher,
             client_ctx->cipher_key_size_in_bits);

  return true;
}

bool tls_set_protocol(tls_client_ctx_t * client_ctx)
{
  const unsigned char * proto = NULL;
  unsigned int proto_len;
  // Check the negotiated protocol in NPN or ALPN
  SSL_get0_next_proto_negotiated(client_ctx->ssl, &proto, &proto_len);

  if (proto) {

    if (proto_len == http2_protocol_version_string_length &&
        memcmp(http2_protocol_version_string, proto, proto_len) == 0) {
      log_append(client_ctx->log, LOG_DEBUG, "Using protocol (through NPN): %s",
          http2_protocol_version_string);
      client_ctx->selected_protocol = http2_protocol_version_string;
      return true;
    }

    if (proto_len == http1_1_protocol_version_string_length &&
        memcmp(http1_1_protocol_version_string, proto, proto_len) == 0) {
      log_append(client_ctx->log, LOG_DEBUG, "Using protocol (through NPN): %s",
          http1_1_protocol_version_string);
      client_ctx->selected_protocol = http1_1_protocol_version_string;
      return true;
    }
  } else {
#ifdef HAVE_ALPN
    SSL_get0_alpn_selected(client_ctx->ssl, &proto, &proto_len);

    if (proto) {

      if (proto_len == http2_protocol_version_string_length &&
          memcmp(http2_protocol_version_string, proto, proto_len) == 0) {
        log_append(client_ctx->log, LOG_DEBUG, "Using protocol (through ALPN): %s",
            http2_protocol_version_string);
        client_ctx->selected_protocol = http2_protocol_version_string;
        return true;
      }

      if (proto_len == http1_1_protocol_version_string_length &&
          memcmp(http1_1_protocol_version_string, proto, proto_len) == 0) {
        log_append(client_ctx->log, LOG_DEBUG, "Using protocol (through ALPN): %s",
            http1_1_protocol_version_string);
        client_ctx->selected_protocol = http1_1_protocol_version_string;
        return true;
      }
    }

#endif
  }

  log_append(client_ctx->log, LOG_DEBUG, "Did not negotiate protocol");
  return false;
}

/**
 * Returns false if the handshake fails or TLS handling cannot continue.
 */
bool tls_decrypt_data_and_pass_to_app(tls_client_ctx_t * client_ctx, uint8_t * buf, size_t length)
{
  log_append(client_ctx->log, LOG_TRACE, "Writing encrypted data to network BIO");

  size_t written = 0;

  do {
    int retval = BIO_write(client_ctx->network_bio, buf + written, length - written);

    if (retval > 0) {
      log_append(client_ctx->log, LOG_TRACE, "Wrote %d/%zu octets of encrypted data to network BIO for decryption",
          retval, length);
      written += retval;
    } else if (BIO_should_retry(client_ctx->network_bio)) {
      // the network BIO buffer maybe full - try freeing some space by
      // reading from it and passing it on to the app
      if (!tls_read_decrypted_data_and_pass_to_app(client_ctx)) {
        log_append(client_ctx->log, LOG_ERROR,
                   "Could not write encrypted data to network BIO for decryption: %d (should retry)", retval);
        free(buf);

        return true;
      }

      // otherwise try again
    } else {
      // fatal error
      log_append(client_ctx->log, LOG_ERROR, "Could not write encrypted data to network BIO for decryption: %d", retval);
      free(buf);

      return false;
    }
  } while (written < length);

  free(buf);

  if (!client_ctx->handshake_complete) {

    log_append(client_ctx->log, LOG_TRACE, "Attempting handshake");
    int retval = SSL_do_handshake(client_ctx->ssl);

    if (retval == 1) {

      if (!tls_set_version(client_ctx)) {
        log_append(client_ctx->log, LOG_WARN, "Handshake complete, blacklisted cipher: %s",
            client_ctx->selected_cipher);
        return false;
      }

      tls_set_protocol(client_ctx);

      // success
      client_ctx->handshake_complete = true;
      log_append(client_ctx->log, LOG_TRACE, "Handshake complete");

    } else if (tls_ssl_wants_read(client_ctx->ssl, retval)) {
      log_append(client_ctx->log, LOG_TRACE, "Handshake not yet complete, should read");
    } else if (tls_ssl_wants_write(client_ctx->ssl, retval)) {
      log_append(client_ctx->log, LOG_TRACE, "Handshake not yet complete, should write");
    } else {
      tls_debug_error(client_ctx->ssl, retval, "Handshake failed");
      return false;
    }

  }

  return tls_update(client_ctx);
}

bool tls_encrypt_data_and_pass_to_network(tls_client_ctx_t * client_ctx, uint8_t * buf, size_t length)
{

  log_append(client_ctx->log, LOG_TRACE, "Encrypting %zu octets of data from application", length);

  size_t written = 0;
  size_t remaining_length = length;

  do {
    int retval = SSL_write(client_ctx->ssl, buf + written, length - written);

    if (retval > 0) {
      log_append(client_ctx->log, LOG_TRACE, "SSL_write returned: %d", retval);
      written += retval;
    } else if (tls_ssl_wants_read(client_ctx->ssl, retval)) {
      log_append(client_ctx->log, LOG_TRACE, "SSL_write: wants read with %zu bytes remaining", remaining_length);

      // the ssl write buffer may be full, try to clear it out by
      // reading the already encrypted data from it
      if (!tls_read_encrypted_data_and_pass_to_network(client_ctx)) {
        return false;
      }

      // try again
    } else if (tls_ssl_wants_write(client_ctx->ssl, retval)) {
      log_append(client_ctx->log, LOG_DEBUG, "SSL_write: wants write with %zu bytes remaining", remaining_length);

      if (!tls_read_encrypted_data_and_pass_to_network(client_ctx)) {
        return false;
      }

      // try again
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

