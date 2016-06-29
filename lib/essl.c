/**
*******************************************************************************
* @file essl.c
* @author Keidan
* @par Project essl
* @copyright Copyright 2016 Keidan, all right reserved.
* @par License:
* This software is distributed in the hope that it will be useful, but WITHOUT
* ANY WARRANTY.
*
* Licence summary : 
*    You can modify and redistribute the sources code and binaries.
*    You can send me the bug-fix
*
* Term of the licence in in the file licence.txt.
*
* .____    ._____.                             
* |    |   |__\_ |__                           
* |    |   |  || __ \
* |    |___|  || \_\ \
* |_______ \__||___  /                         
*         \/       \/                          
* ___________                                  
* \_   _____/____    _________.__.             
*  |    __)_\__  \  /  ___<   |  |             
*  |        \/ __ \_\___ \ \___  |             
* /_______  (____  /____  >/ ____|             
*         \/     \/     \/ \/                  
*   _________ _________.____     
*  /   _____//   _____/|    |    
*  \_____  \ \_____  \ |    |    
*  /        \/        \|    |___ 
* /_______  /_______  /|_______ \
*         \/        \/         \/
*
*******************************************************************************
*/
#include <stdio.h>
#include <essl.h>
#include <math.h>
#ifndef OPENSSL_NO_BIO
  #include <openssl/bio.h>
#endif /* OPENSSL_NO_BIO */
#ifndef OPENSSL_NO_EVP
  #include <openssl/evp.h>
#endif /* OPENSSL_NO_EVP */
#ifndef OPENSSL_NO_HMAC
  #include <openssl/hmac.h>
#endif /* OPENSSL_NO_HMAC */
#ifndef OPENSSL_NO_BUFFER
  #include <openssl/buffer.h>
#endif /* OPENSSL_NO_BUFFER */
#ifndef OPENSSL_NO_SSL2
  #include <openssl/ssl.h>
#endif /* OPENSSL_NO_SSL2 */
#ifndef OPENSSL_NO_ERR
  #include <openssl/err.h>
#endif /* OPENSSL_NO_ERR */

/****************************************************
 * ________          _____.__                                 
 * \______ \   _____/ ____\__| ____   ____   ______           
 *  |    |  \_/ __ \   __\|  |/    \_/ __ \ /  ___/           
 *  |    `   \  ___/|  |  |  |   |  \  ___/ \___ \
 * /_______  /\___  >__|  |__|___|  /\___  >____  >           
 *         \/     \/              \/     \/     \/ 
 *****************************************************/
/**
 * @def ESSL_DEFAULT_BUFFER_LENGTH
 * @brief The default buffer length used by the API.
 */
#define ESSL_DEFAULT_BUFFER_LENGTH 1024


/*****************************************************
 *    _____  ________   ________  
 *   /     \ \______ \  \_____  \
 *  /  \ /  \ |    |  \  /  ____/ 
 * /    Y    \|    `   \/       \
 * \____|__  /_______  /\_______ \
 *         \/        \/         \/                               
 *****************************************************/
#ifndef OPENSSL_NO_MD2
/**
 * @fn void essl_md2_do_hash(const char* str, size_t length, essl_md2_digest_t result) 
 * @brief Generate a MD2 digest
 * @param str String to hash
 * @param length String length to hash
 * @param result Output hash
 */
void essl_md2_do_hash(const char* str, size_t length, essl_md2_digest_t result) {
  MD2_CTX md2_ctx;
  MD2_Init(&md2_ctx);
  MD2_Update(&md2_ctx, (unsigned char*)str, length);
  MD2_Final(result, &md2_ctx);
}

/**
 * @fn void essl_md2_digest_to_string(essl_md2_digest_t digest, essl_md2_string_t str)
 * @brief Convert a MD2 hash to hexa string.
 * @param digest MD2 hash
 * @param str Output string.
 */
void essl_md2_digest_to_string(essl_md2_digest_t digest, essl_md2_string_t str) { 
  size_t i;
  for (i = 0; i < ESSL_MD2_DIGEST_LENGTH; i++)
    sprintf(&str[i*2], "%02x", (unsigned int)digest[i]);
}

/**
 * @fn void essl_md2_do_hash_file(const char* filename, essl_md2_digest_t result) 
 * @brief Generate a MD5 digest of a file
 * @param filename The file to hash
 * @param result Output hash
 * @return -1 on error, 0 else (see errno for more details).
 */
int essl_md2_do_hash_file(const char* filename, essl_md5_digest_t result) {
  MD2_CTX md2_ctx;
  int bytes;
  unsigned char data[ESSL_DEFAULT_BUFFER_LENGTH];
  FILE *file = fopen(filename, "rb");
  if(file == NULL) return -1;
  MD2_Init(&md2_ctx);
  while((bytes = fread(data, 1, ESSL_DEFAULT_BUFFER_LENGTH, file)) != 0)
    MD2_Update(&md2_ctx, data, bytes);
  MD2_Final(result, &md2_ctx);
  fclose(file);
  errno = 0;
  return 0;
}
#endif /* OPENSSL_NO_MD2 */


/*****************************************************
 *    _____  ________      _____  
 *   /     \ \______ \    /  |  | 
 *  /  \ /  \ |    |  \  /   |  |_
 * /    Y    \|    `   \/    ^   /
 * \____|__  /_______  /\____   | 
 *         \/        \/      |__| 
 *****************************************************/
#ifndef OPENSSL_NO_MD4
/**
 * @fn void essl_md4_do_hash(const char* str, size_t length, essl_md4_digest_t result) 
 * @brief Generate a MD4 digest
 * @param str String to hash
 * @param length String length to hash
 * @param result Output hash
 */
void essl_md4_do_hash(const char* str, size_t length, essl_md4_digest_t result) {
  MD4_CTX md4_ctx;
  MD4_Init(&md4_ctx);
  MD4_Update(&md4_ctx, str, length);
  MD4_Final(result, &md4_ctx);
}

/**
 * @fn void essl_md4_digest_to_string(essl_md4_digest_t digest, essl_md4_string_t str)
 * @brief Convert a MD4 hash to hexa string.
 * @param digest MD4 hash
 * @param str Output string.
 */
void essl_md4_digest_to_string(essl_md4_digest_t digest, essl_md4_string_t str) { 
  size_t i;
  for (i = 0; i < ESSL_MD4_DIGEST_LENGTH; i++)
    sprintf(&str[i*2], "%02x", (unsigned int)digest[i]);
}

/**
 * @fn void essl_md4_do_hash_file(const char* filename, essl_md4_digest_t result) 
 * @brief Generate a MD4 digest of a file
 * @param filename The file to hash
 * @param result Output hash
 * @return -1 on error, 0 else (see errno for more details).
 */
int essl_md4_do_hash_file(const char* filename, essl_md4_digest_t result) {
  MD4_CTX md4_ctx;
  int bytes;
  unsigned char data[ESSL_DEFAULT_BUFFER_LENGTH];
  FILE *file = fopen(filename, "rb");
  if(file == NULL) return -1;
  MD4_Init(&md4_ctx);
  while((bytes = fread(data, 1, ESSL_DEFAULT_BUFFER_LENGTH, file)) != 0)
    MD4_Update(&md4_ctx, data, bytes);
  MD4_Final(result, &md4_ctx);
  fclose(file);
  errno = 0;
  return 0;
}
#endif /* OPENSSL_NO_MD4 */


/*****************************************************
 *    _____  ________   .________
 *   /     \ \______ \  |   ____/
 *  /  \ /  \ |    |  \ |____  \
 * /    Y    \|    `   \/	\
 * \____|__  /_______  /______  /
 *         \/        \/       \/                                  
 *****************************************************/
#ifndef OPENSSL_NO_MD5
/**
 * @fn void essl_md5_do_hash(const char* str, size_t length, essl_md5_digest_t result) 
 * @brief Generate a MD5 digest
 * @param str String to hash
 * @param length String length to hash
 * @param result Output hash
 */
void essl_md5_do_hash(const char* str, size_t length, essl_md5_digest_t result) {
  MD5_CTX md5_ctx;
  MD5_Init(&md5_ctx);
  MD5_Update(&md5_ctx, str, length);
  MD5_Final(result, &md5_ctx);
}

/**
 * @fn void essl_md5_digest_to_string(essl_md5_digest_t digest, essl_md5_string_t str)
 * @brief Convert a MD5 hash to hexa string.
 * @param digest MD5 hash
 * @param str Output string.
 */
void essl_md5_digest_to_string(essl_md5_digest_t digest, essl_md5_string_t str) { 
  size_t i;
  for (i = 0; i < ESSL_MD5_DIGEST_LENGTH; i++)
    sprintf(&str[i*2], "%02x", (unsigned int)digest[i]);
}

/**
 * @fn void essl_md5_do_hash_file(const char* filename, essl_md5_digest_t result) 
 * @brief Generate a MD5 digest of a file
 * @param filename The file to hash
 * @param result Output hash
 * @return -1 on error, 0 else (see errno for more details).
 */
int essl_md5_do_hash_file(const char* filename, essl_md5_digest_t result) {
  MD5_CTX md5_ctx;
  int bytes;
  unsigned char data[ESSL_DEFAULT_BUFFER_LENGTH];
  FILE *file = fopen(filename, "rb");
  if(file == NULL) return -1;
  MD5_Init(&md5_ctx);
  while((bytes = fread(data, 1, ESSL_DEFAULT_BUFFER_LENGTH, file)) != 0)
    MD5_Update(&md5_ctx, data, bytes);
  MD5_Final(result, &md5_ctx);
  fclose(file);
  errno = 0;
  return 0;
}
#endif /* OPENSSL_NO_MD5 */


/*****************************************************
 * __________    _____    ____________________   ________   _____  
 * \______   \  /  _  \  /   _____/\_   _____/  /  _____/  /  |  | 
 *  |    |  _/ /  /_\  \ \_____  \  |    __)_  /   __  \  /   |  |_
 *  |    |   \/    |    \/        \ |        \ \  |__\  \/    ^   /
 *  |______  /\____|__  /_______  //_______  /  \_____  /\____   | 
 *         \/         \/        \/         \/         \/      |__| 
 *****************************************************/
#ifndef OPENSSL_NO_BIO
/**
 * @fn int essl_base64_encode(const char *input, const size_t ilength, char** output, size_t *olength)
 * @brief Encode a paln text to a base64 representation.
 * @param input The plain text to encode.
 * @param ilength The plain text length.
 * @param output The encoded message in base64 (free required)
 * @param olength The encoded message length.
 * @return -1 on error, 0 else (see errno for more details).
 */ 
int essl_base64_encode(const char *input, const size_t ilength, char** output, size_t *olength) {
  BIO *bio;
  BIO *base64;
  FILE* file;
  int esize = 4 * ceil((double)ilength / 3);
  *output = malloc(esize + 1);
  if(*output == NULL) {
    errno = ENOMEM;
    return -1;
  }
  *olength = esize;
  file = fmemopen(*output, esize + 1, "w");
  if(*output == NULL) {
    *olength = 0;
    free(*output);
    errno = EIO;
    return -1;
  }
  base64 = BIO_new(BIO_f_base64());
  bio = BIO_new_fp(file, BIO_NOCLOSE);
  bio = BIO_push(base64, bio);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
  BIO_write(bio, input, ilength);
  (void)BIO_flush(bio);
  BIO_free_all(bio);
  fclose(file);
  errno = 0;
  return 0;
}
 
/**
 * @fn int essl_base64_decode(const char *input, const size_t ilength, char **output, size_t *olength)
 * @brief Decode a base64 message to a plain text.
 * @param input The message in base64
 * @param ilength  The length of the base64 message
 * @param output The plain text message (free required).
 * @param olength The decoded message length.
 * @return -1 on error, 0 else (see errno for more details).
 */ 
int essl_base64_decode(const char *input, const size_t ilength, char **output, size_t *olength) {
  BIO *bio;
  BIO *base64;
  FILE* file;
  int dsize = essl_base64_adjust_decode_length(input, ilength);

  *output = malloc(dsize + 1);
  if(*output == NULL) {
    errno = ENOMEM;
    return -1;
  }
  file = fmemopen((void*)input, ilength, "r");
  if(*output == NULL) {
    free(*output);
    errno = EIO;
    return -1;
  }
  base64 = BIO_new(BIO_f_base64());
  bio = BIO_new_fp(file, BIO_NOCLOSE);
  bio = BIO_push(base64, bio);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
  dsize = BIO_read(bio, *output, ilength);
  (*output)[dsize] = '\0';
     
  BIO_free_all(bio);
  fclose(file);
  *olength = dsize;
  errno = 0;
  return 0;
}

/**
 * @fn size_t essl_base64_adjust_decode_length(const char *input, const size_t ilength)
 * @brief Adjust the length of the decoded message.
 * @param input The base64 buffer length
 * @param olength The encoded message length.
 * @return The decoded length of the base64 message.
 */
size_t essl_base64_adjust_decode_length(const char *input, const size_t ilength) {
  size_t padding = 0;
  /* Check for trailing '=''s as padding */
  if(input[ilength-1] == '=' && input[ilength-2] == '=')
    padding = 2;
  else if (input[ilength-1] == '=')
    padding = 1;
  return ilength*0.75 - padding;
}
#endif /* OPENSSL_NO_BIO */


/*****************************************************
 *   _________ ___ ___    _____  ____ 
 *  /   _____//   |   \  /  _  \/_   |
 *  \_____  \/    ~    \/  /_\  \|   |
 *  /        \    Y    /    |    \   |
 * /_______  /\___|_  /\____|__  /___|
 *         \/       \/         \/     
 *****************************************************/
#ifndef OPENSSL_NO_SHA1
/**
 * @fn int essl_sha1_do_hash(const char* input, size_t ilength, essl_sha1_string_t output)
 * @brief Calculate a SHA1 for a specified string.
 * @param input The plain text to encode.
 * @param ilength The plain text length.
 * @param output The encoded output string.
 * @return -1 on error, 0 else (see errno for more details).
 */
int essl_sha1_do_hash(const char* input, size_t ilength, essl_sha1_string_t output) {
  unsigned char buffer[ESSL_SHA_DIGEST_LENGTH];
  SHA_CTX sha_ctx;
  int i, j;
  bzero(buffer, ESSL_SHA_DIGEST_LENGTH);;
  memset(&sha_ctx, 0, sizeof(SHA_CTX));
  
  SHA1_Init(&sha_ctx);
  SHA1_Update(&sha_ctx, input, ilength);
  SHA1_Final(buffer, &sha_ctx);
  for(i = 0, j = 0; i < ESSL_SHA_DIGEST_LENGTH; i++, j+=2)
    sprintf(output + j, "%02x", buffer[i]);
  return 0;
}

/**
 * @fn int essl_sha1_do_hash_file(const char* filename, essl_sha1_string_t output)
 * @brief Calculate a SHA1 for a specified file.
 * @param filename The file name.
 * @param output The output buffer with the sha1.
 * @return -1 on error, 0 else (see errno for more details).
 */
int essl_sha1_do_hash_file(const char* filename, essl_sha1_string_t output) {
  FILE *file;
  unsigned char buf[ESSL_DEFAULT_BUFFER_LENGTH];
  unsigned char buffer[ESSL_SHA_DIGEST_LENGTH];
  SHA_CTX sha_ctx;
  size_t len;
  int i, j;
  bzero(buffer, ESSL_SHA_DIGEST_LENGTH);
  bzero(buf, ESSL_DEFAULT_BUFFER_LENGTH);
  memset(&sha_ctx, 0, sizeof(SHA_CTX));

  file = fopen(filename, "rb");
  if(!file) return -1;
  
  SHA1_Init(&sha_ctx);
  for (;;) {
    len = fread(buf, 1, ESSL_DEFAULT_BUFFER_LENGTH, file);
    if (len == 0) break;
    SHA1_Update(&sha_ctx, buf, len);
  }
  fclose(file);
  SHA1_Final(buffer, &sha_ctx);
  for(i = 0, j = 0; i < ESSL_SHA_DIGEST_LENGTH; i++, j+=2)
    sprintf(output + j, "%02x", buffer[i]);
  return 0;
}
#endif /* OPENSSL_NO_SHA */


/*****************************************************
 *   _________________  _________  ____  __.______________________
 *  /   _____/\_____  \ \_   ___ \|    |/ _|\_   _____/\__    ___/
 *  \_____  \  /   |   \/    \  \/|      <   |    __)_   |    |
 *  /        \/    |    \     \___|    |  \  |        \  |    |
 * /_______  /\_______  /\______  /____|__ \/_______  /  |____|
 *         \/         \/        \/        \/        \/
 *****************************************************/

#if !defined(OPENSSL_NO_SSL2) && !defined(OPENSSL_NO_BIO)
  
unsigned long essl_errno = 0;

struct essl_context_ssl_s {
  SSL_CTX *ctx;
  SSL     *ssl;
};

#ifndef OPENSSL_NO_ERR
#define essl_update_errno() essl_errno = ERR_get_error()
#else
#define essl_update_errno() essl_errno = 0
#endif /* OPENSSL_NO_ERR */

/**
 * @fn int essl_initialize_ssl(void)
 * @brief Initialize the SSL stack, should be called only once in your application.
 * @return -1 if the initialization fail, 0 else.
 */
int essl_initialize_ssl(void) {
  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();
  SSL_load_error_strings();
  if(SSL_library_init() < 0) {
    essl_update_errno();
    essl_release_ssl();
    return -1;
  }
  return 0;
}
/**
 * @fn void essl_initialize_ssl(void)
 * @brief Release the SSL stack, should be called only once in your application.
 */
void essl_release_ssl(void) {
  ERR_free_strings();
  EVP_cleanup();
}

/**
 * @fn const char* essl_strerror_ssl(void)
 * @brief Get the string representation of the essl_errno value in a static buffer.
 * @return NULL if OPENSSL_NO_ERR is defined else the string error.
 */
const char* essl_strerror_ssl(void) {
#ifndef OPENSSL_NO_ERR
  return ERR_error_string(essl_errno, NULL);
#else
  return NULL;
#endif /* OPENSSL_NO_ERR */
}

/**
 * @fn static int essl_dumb_callback(int preverify_ok, X509_STORE_CTX *ctx)
 * @brief Dumb callback used by the SSL_CTX_set_verify function.
 * @param preverify_ok preverify ok.
 * @param ctx X509 store context.
 * @return 1 to continue.
 */
static int essl_dumb_callback(int preverify_ok, X509_STORE_CTX *ctx) {
  (void)preverify_ok;
  (void)ctx;
  return 1;
}

/**
 * @fn void essl_close_ssl(essl_socket_t essl)
 * @brief Close the resources allocated by the connect/accept functions (does not close the user FD).
 * @param essl The context to close.
 */
void essl_close_ssl(essl_socket_t essl) {
  struct essl_context_ssl_s *e = (struct essl_context_ssl_s*)essl;
  if(e) {
    if(e->ssl) {
      SSL_shutdown(e->ssl);
      SSL_free(e->ssl);
      e->ssl = NULL;
    }
    if(e->ctx) {
      SSL_CTX_free(e->ctx);
      e->ctx = NULL;
    }
    free(e);
  }
}

/**
 * @fn static essl_socket_t essl_connect_or_accept_ssl(int fd, int accept)
 * @brief Bind an suer socket fd to the SSL context.
 * @param fd The user FD to bind.
 * @param accept 0 for connect method, 1 for accept method.
 * @return NULL on error, else the SSL context.
 */
static essl_socket_t essl_connect_or_accept_ssl(int fd, int accept) {  
  struct essl_context_ssl_s *essl = NULL;
  
  if((essl = malloc(sizeof(struct essl_context_ssl_s))) == NULL) {
    essl_errno = ERR_R_MALLOC_FAILURE;
    return NULL;
  }
  
  /* We first need to establish what sort of */
  /* connection we know how to make. We can use one of */
  /* SSLv23_client_method(), SSLv2_client_method() and */
  /* SSLv3_client_method(). */
  /*  Try to create a new SSL context. */
  if((essl->ctx = SSL_CTX_new(SSLv23_client_method())) == NULL) {
    essl_update_errno();
    free(essl);
    return NULL;
  }

  /* Set it up so tha we will connect to *any* site, regardless of their certificate. */
  SSL_CTX_set_verify(essl->ctx, SSL_VERIFY_NONE, essl_dumb_callback);
  /* Enable bug support hacks. */
  SSL_CTX_set_options(essl->ctx, SSL_OP_ALL);

  /* Create new SSL connection state object. */
  essl->ssl = SSL_new(essl->ctx);
  if(essl->ssl == NULL) {
    essl_update_errno();
    SSL_CTX_free(essl->ctx);
    free(essl);
    return NULL;
  }
  /* Attach the SSL session. */
  SSL_set_fd(essl->ssl, fd);
  if(!accept) {
    /* Connect using the SSL session. */
    if(SSL_connect(essl->ssl) != 1) {
      essl_update_errno();
      SSL_shutdown(essl->ssl);
      SSL_free(essl->ssl);
      SSL_CTX_free(essl->ctx);
      free(essl);
      return NULL;
    }
  } else {
    /* Accept using the SSL session. */
    if(SSL_accept(essl->ssl) != 1) {
      essl_update_errno();
      SSL_shutdown(essl->ssl);
      SSL_free(essl->ssl);
      SSL_CTX_free(essl->ctx);
      free(essl);
      return NULL;
    }
  }
  return essl;
}

/**
 * @fn essl_socket_t essl_connect_ssl(int fd)
 * @brief Bind an suer socket fd to the SSL context.
 * @param fd The user FD to bind.
 * @return NULL on error, else the SSL context.
 */
essl_socket_t essl_connect_ssl(int fd) {
  return essl_connect_or_accept_ssl(fd, 0);
}

/**
 * @fn essl_socket_t essl_accept_ssl(int fd)
 * @brief Bind an user socket fd to the SSL context.
 * @param fd The user FD to bind.
 * @return NULL on error, else the SSL context.
 */
essl_socket_t essl_accept_ssl(int fd) {
  return essl_connect_or_accept_ssl(fd, 1);
}

/**
 * @fn int essl_write_ssl(essl_socket_t essl, const void* buffer, size_t length)
 * @brief Write a buffer into the specified ssl connection.
 * @param essl The SSL context.
 * @param buffer The buffer to write.
 * @param length The buffer length.
 * @return 
 * >0 The write operation was successful, the return value is the number of bytes actually written to the TLS/SSL connection.
 * =0 The write operation was not successful. Probably the underlying connection was closed. Call SSL_get_error() with the return value ret to find out, whether an error occurred or the connection was shut down cleanly (SSL_ERROR_ZERO_RETURN).
 * <0 The write operation was not successful, because either an error occurred or action must be taken by the calling process. See essl_errno to find out the reason.
*/
int essl_write_ssl(essl_socket_t essl, const void* buffer, size_t length) {
  int r;
  struct essl_context_ssl_s *e = (struct essl_context_ssl_s*)essl;
  if(!e) {
    essl_errno = ERR_R_PASSED_NULL_PARAMETER;
    return -1;
  }
  r = SSL_write(e->ssl, buffer, length);
  if(r < 0) essl_errno = r;
  return r;
}

/**
 * @fn int essl_read_ssl(essl_socket_t essl, void* buffer, size_t length)
 * @brief Read a buffer from the specified ssl connection.
 * @param essl The SSL context.
 * @param buffer The buffer to read.
 * @param length The buffer length.
 * @return 
 * >0 The read operation was successful; the return value is the number of bytes actually read from the TLS/SSL connection.
 * =0 The read operation was not successful. The reason may either be a clean shutdown due to a "close notify" alert sent by the peer (in which case the SSL_RECEIVED_SHUTDOWN flag in the ssl shutdown state is set (see SSL_shutdown, SSL_set_shutdown). It is also possible, that the peer simply shut down the underlying transport and the shutdown is incomplete. Call SSL_get_error() with the return value ret to find out, whether an error occurred or the connection was shut down cleanly (SSL_ERROR_ZERO_RETURN).
 * <0 The read operation was not successful, because either an error occurred or action must be taken by the calling process. See essl_errno to find out the reason.
*/
int essl_read_ssl(essl_socket_t essl, void* buffer, size_t length) {
  int r;
  struct essl_context_ssl_s *e = (struct essl_context_ssl_s*)essl;
  if(!e) {
    essl_errno = ERR_R_PASSED_NULL_PARAMETER;
    return -1;
  }
  r = SSL_read(e->ssl, buffer, length);
  if(r < 0) essl_errno = r;
  return r;
}

#endif /* OPENSSL_NO_SSL2 && OPENSSL_NO_BIO */

