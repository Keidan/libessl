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
#ifndef EVP_MD
#include <openssl/evp.h>
#include <openssl/aes.h>
#endif /* EVP_MD */

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
 * _______________________________ ________ __________ 
 * \_   _____/\______   \______   \\_____  \\______   \
 *  |    __)_  |       _/|       _/ /   |   \|       _/
 *  |        \ |    |   \|    |   \/    |    \    |   \
 * /_______  / |____|_  /|____|_  /\_______  /____|_  /
 *         \/         \/        \/         \/       \/        
 *****************************************************/

uint64_t essl_errno = 0ULL;

#ifndef ESSL_SUPPORT_ERROR
#define essl_update_errno() essl_errno = ERR_get_error()
#else
#define essl_update_errno() essl_errno = 0
#endif /* ESSL_SUPPORT_ERROR */

/**
 * @brief Get the string representation of the essl_errno value in a static buffer.
 * @return NULL if ESSL_SUPPORT_ERROR is not defined otherwise the string error.
 */
const char* essl_strerror(void)
{
#ifdef ESSL_SUPPORT_ERROR
  return ERR_error_string(essl_errno, NULL);
#else
  return NULL;
#endif /* ESSL_SUPPORT_ERROR */
}

/*****************************************************
 *    _____  ________   ________  
 *   /     \ \______ \  \_____  \
 *  /  \ /  \ |    |  \  /  ____/ 
 * /    Y    \|    `   \/       \
 * \____|__  /_______  /\_______ \
 *         \/        \/         \/                               
 *****************************************************/
#ifdef ESSL_SUPPORT_MD2
/**
 * @brief Generate a MD2 digest
 * @param[in] str String to hash
 * @param[in] length String length to hash
 * @param[out] result Output hash
 */
void essl_md2_do_hash(const char* str, size_t length, essl_md2_digest_t result)
{
  MD2_CTX md2_ctx;
  MD2_Init(&md2_ctx);
  MD2_Update(&md2_ctx, (unsigned char*)str, length);
  MD2_Final(result, &md2_ctx);
}

/**
 * @brief Convert a MD2 hash to hexa string.
 * @param[in] digest MD2 hash
 * @param[out] str Output string.
 */
void essl_md2_digest_to_string(essl_md2_digest_t digest, essl_md2_string_t str)
{ 
  size_t i;
  for (i = 0; i < ESSL_MD2_DIGEST_LENGTH; i++)
    sprintf(&str[i*2], "%02x", (unsigned int)digest[i]);
}

/**
 * @brief Generate a MD5 digest of a file
 * @param[in] filename The file to hash
 * @param[out] result Output hash
 * @return -1 on error, otherwise 0 (see errno for more details).
 */
int essl_md2_do_hash_file(const char* filename, essl_md5_digest_t result)
{
  MD2_CTX md2_ctx;
  int bytes;
  uint8_t data[ESSL_DEFAULT_BUFFER_LENGTH];
  FILE* file = fopen(filename, "rb");
  if(file == NULL)
    return -1;
  MD2_Init(&md2_ctx);
  while((bytes = fread(data, 1, ESSL_DEFAULT_BUFFER_LENGTH, file)) != 0)
    MD2_Update(&md2_ctx, data, bytes);
  MD2_Final(result, &md2_ctx);
  fclose(file);
  errno = 0;
  return 0;
}
#endif /* ESSL_SUPPORT_MD2 */


/*****************************************************
 *    _____  ________      _____  
 *   /     \ \______ \    /  |  | 
 *  /  \ /  \ |    |  \  /   |  |_
 * /    Y    \|    `   \/    ^   /
 * \____|__  /_______  /\____   | 
 *         \/        \/      |__| 
 *****************************************************/
#ifdef ESSL_SUPPORT_MD4
/**
 * @brief Generate a MD4 digest
 * @param[in] str String to hash
 * @param[in] length String length to hash
 * @param[out] result Output hash
 */
void essl_md4_do_hash(const char* str, size_t length, essl_md4_digest_t result)
{
  MD4_CTX md4_ctx;
  MD4_Init(&md4_ctx);
  MD4_Update(&md4_ctx, str, length);
  MD4_Final(result, &md4_ctx);
}

/**
 * @brief Convert a MD4 hash to hexa string.
 * @param[in] digest MD4 hash
 * @param[out] str Output string.
 */
void essl_md4_digest_to_string(essl_md4_digest_t digest, essl_md4_string_t str)
{ 
  size_t i;
  for (i = 0; i < ESSL_MD4_DIGEST_LENGTH; i++)
    sprintf(&str[i*2], "%02x", (unsigned int)digest[i]);
}

/**
 * @brief Generate a MD4 digest of a file
 * @param[in] filename The file to hash
 * @param[out] result Output hash
 * @return -1 on error, otherwise 0 (see errno for more details).
 */
int essl_md4_do_hash_file(const char* filename, essl_md4_digest_t result)
{
  MD4_CTX md4_ctx;
  int bytes;
  uint8_t data[ESSL_DEFAULT_BUFFER_LENGTH];
  FILE* file = fopen(filename, "rb");
  if(file == NULL)
    return -1;
  MD4_Init(&md4_ctx);
  while((bytes = fread(data, 1, ESSL_DEFAULT_BUFFER_LENGTH, file)) != 0)
    MD4_Update(&md4_ctx, data, bytes);
  MD4_Final(result, &md4_ctx);
  fclose(file);
  errno = 0;
  return 0;
}
#endif /* ESSL_SUPPORT_MD4 */


/*****************************************************
 *    _____  ________   .________
 *   /     \ \______ \  |   ____/
 *  /  \ /  \ |    |  \ |____  \
 * /    Y    \|    `   \/	\
 * \____|__  /_______  /______  /
 *         \/        \/       \/                                  
 *****************************************************/
#ifdef ESSL_SUPPORT_MD5
/**
 * @brief Generate a MD5 digest
 * @param[in] str String to hash
 * @param[in] length String length to hash
 * @param[out] result Output hash
 */
void essl_md5_do_hash(const char* str, size_t length, essl_md5_digest_t result)
{
  MD5_CTX md5_ctx;
  MD5_Init(&md5_ctx);
  MD5_Update(&md5_ctx, str, length);
  MD5_Final(result, &md5_ctx);
}

/**
 * @brief Convert a MD5 hash to hexa string.
 * @param[in] digest MD5 hash
 * @param[out] str Output string.
 */
void essl_md5_digest_to_string(essl_md5_digest_t digest, essl_md5_string_t str)
{ 
  size_t i;
  for (i = 0; i < ESSL_MD5_DIGEST_LENGTH; i++)
    sprintf(&str[i*2], "%02x", (unsigned int)digest[i]);
}

/**
 * @brief Generate a MD5 digest of a file
 * @param[in] filename The file to hash
 * @param[out] result Output hash
 * @return -1 on error, otherwise 0 (see errno for more details).
 */
int essl_md5_do_hash_file(const char* filename, essl_md5_digest_t result)
{
  MD5_CTX md5_ctx;
  int bytes;
  uint8_t data[ESSL_DEFAULT_BUFFER_LENGTH];
  FILE* file = fopen(filename, "rb");
  if(file == NULL)
    return -1;
  MD5_Init(&md5_ctx);
  while((bytes = fread(data, 1, ESSL_DEFAULT_BUFFER_LENGTH, file)) != 0)
    MD5_Update(&md5_ctx, data, bytes);
  MD5_Final(result, &md5_ctx);
  fclose(file);
  errno = 0;
  return 0;
}
#endif /* ESSL_SUPPORT_MD5 */


/*****************************************************
 * __________    _____    ____________________   ________   _____  
 * \______   \  /  _  \  /   _____/\_   _____/  /  _____/  /  |  | 
 *  |    |  _/ /  /_\  \ \_____  \  |    __)_  /   __  \  /   |  |_
 *  |    |   \/    |    \/        \ |        \ \  |__\  \/    ^   /
 *  |______  /\____|__  /_______  //_______  /  \_____  /\____   | 
 *         \/         \/        \/         \/         \/      |__| 
 *****************************************************/
#ifdef ESSL_SUPPORT_BASE64
/**
 * @brief Encode a paln text to a base64 representation.
 * @param[in] input The plain text to encode.
 * @param[in] ilength The plain text length.
 * @param[out] output The encoded message in base64 (free required)
 * @param[out] olength The encoded message length.
 * @return -1 on error, otherwise 0 (see errno for more details).
 */ 
int essl_base64_encode(const char* input, const size_t ilength, char** output, size_t* olength)
{
  BIO* bio;
  BIO* base64;
  FILE* file;
  int esize = 4 * ceil((double)ilength / 3);
  *output = malloc(esize + 1);
  if(*output == NULL)
  {
    errno = ENOMEM;
    return -1;
  }
  *olength = esize;
  file = fmemopen(*output, esize + 1, "w");
  if(*output == NULL)
  {
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
 * @brief Decode a base64 message to a plain text.
 * @param[in] input The message in base64
 * @param[in] ilength  The length of the base64 message
 * @param[out] output The plain text message (free required).
 * @param[out] olength The decoded message length.
 * @return -1 on error, otherwise 0 (see errno for more details).
 */ 
int essl_base64_decode(const char* input, const size_t ilength, char**output, size_t* olength)
{
  BIO* bio;
  BIO* base64;
  FILE* file;
  int dsize = essl_base64_adjust_decode_length(input, ilength);

  *output = malloc(dsize + 1);
  if(*output == NULL)
  {
    errno = ENOMEM;
    return -1;
  }
  file = fmemopen((void*)input, ilength, "r");
  if(*output == NULL)
  {
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
 * @brief Adjust the length of the decoded message.
 * @param[in] input The base64 buffer length
 * @param[in] ilength The encoded message length.
 * @return The decoded length of the base64 message.
 */
size_t essl_base64_adjust_decode_length(const char* input, const size_t ilength)
{
  size_t padding = 0;
  /* Check for trailing '=''s as padding */
  if(input[ilength-1] == '=' && input[ilength-2] == '=')
    padding = 2;
  else if (input[ilength-1] == '=')
    padding = 1;
  return ilength*0.75 - padding;
}
#endif /* ESSL_SUPPORT_BASE64 */


/*****************************************************
 *   _________ ___ ___    _____  ____ 
 *  /   _____//   |   \  /  _  \/_   |
 *  \_____  \/    ~    \/  /_\  \|   |
 *  /        \    Y    /    |    \   |
 * /_______  /\___|_  /\____|__  /___|
 *         \/       \/         \/     
 *****************************************************/
#ifdef ESSL_SUPPORT_SHA1
/**
 * @brief Calculate a SHA1 for a specified string.
 * @param[in] input The plain text to encode.
 * @param[in] ilength The plain text length.
 * @param[out] output The encoded output string.
 * @return -1 on error, otherwise 0 (see errno for more details).
 */
int essl_sha1_do_hash(const char* input, size_t ilength, essl_sha1_string_t output)
{
  uint8_t buffer[ESSL_SHA_DIGEST_LENGTH];
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
 * @brief Calculate a SHA1 for a specified file.
 * @param[in] filename The file name.
 * @param[out] output The output buffer with the sha1.
 * @return -1 on error, otherwise 0 (see errno for more details).
 */
int essl_sha1_do_hash_file(const char* filename, essl_sha1_string_t output)
{
  FILE* file;
  uint8_t buf[ESSL_DEFAULT_BUFFER_LENGTH];
  uint8_t buffer[ESSL_SHA_DIGEST_LENGTH];
  SHA_CTX sha_ctx;
  size_t len;
  int i, j;
  bzero(buffer, ESSL_SHA_DIGEST_LENGTH);
  bzero(buf, ESSL_DEFAULT_BUFFER_LENGTH);
  memset(&sha_ctx, 0, sizeof(SHA_CTX));

  file = fopen(filename, "rb");
  if(!file)
    return -1;
  
  SHA1_Init(&sha_ctx);
  for (;;)
  {
    len = fread(buf, 1, ESSL_DEFAULT_BUFFER_LENGTH, file);
    if (len == 0)
      break;
    SHA1_Update(&sha_ctx, buf, len);
  }
  fclose(file);
  SHA1_Final(buffer, &sha_ctx);
  for(i = 0, j = 0; i < ESSL_SHA_DIGEST_LENGTH; i++, j+=2)
    sprintf(output + j, "%02x", buffer[i]);
  return 0;
}
#endif /* ESSL_SUPPORT_SHA1 */


/*****************************************************
 *   _________________  _________  ____  __.______________________
 *  /   _____/\_____  \ \_   ___ \|    |/ _|\_   _____/\__    ___/
 *  \_____  \  /   |   \/    \  \/|      <   |    __)_   |    |
 *  /        \/    |    \     \___|    |  \  |        \  |    |
 * /_______  /\_______  /\______  /____|__ \/_______  /  |____|
 *         \/         \/        \/        \/        \/
 *****************************************************/
#ifdef ESSL_SUPPORT_SOCKET

struct essl_socket_s
{
    SSL_CTX* ctx;
    SSL* ssl;
};

/**
 * @brief Initialize the SSL stack, should be called only once in your application.
 * @return -1 if the initialization fail, otherwise 0.
 */
int essl_socket_initialize(void)
{
  essl_errno = 0ULL;
  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();
  SSL_load_error_strings();
  if(SSL_library_init() < 0)
  {
    essl_update_errno();
    essl_socket_release();
    return -1;
  }
  return 0;
}

/**
 * @brief Release the SSL stack, should be called only once in your application.
 */
void essl_socket_release(void)
{
  ERR_free_strings();
  EVP_cleanup();
}

/**
 * @brief Dumb callback used by the SSL_CTX_set_verify function.
 * @param[in] preverify_ok preverify ok.
 * @param[in] ctx X509 store context.
 * @return 1 to continue.
 */
static int essl_socket_dumb_callback(int preverify_ok, X509_STORE_CTX* ctx)
{
  (void)preverify_ok;
  (void)ctx;
  return 1;
}

/**
 * @brief Close the resources allocated by the connect/accept functions (does not close the user FD).
 * @param[in] essl The context to close.
 */
void essl_socket_close(essl_socket_t essl)
{
  struct essl_socket_s* e = (struct essl_socket_s*)essl;
  essl_errno = 0ULL;
  if(e)
  {
    if(e->ssl)
    {
      SSL_shutdown(e->ssl);
      SSL_free(e->ssl);
      e->ssl = NULL;
    }
    if(e->ctx)
    {
      SSL_CTX_free(e->ctx);
      e->ctx = NULL;
    }
    free(e);
  }
}

/**
 * @brief Bind an suer socket fd to the SSL context.
 * @param[in] fd The user FD to bind.
 * @return NULL on error, otherwise the SSL context.
 */
essl_socket_t essl_socket_connect(int fd)
{
  struct essl_socket_s* e = NULL;
  
  essl_errno = 0ULL;
  if((e = malloc(sizeof(struct essl_socket_s))) == NULL)
  {
    essl_errno = ERR_PACK(ERR_LIB_USER, SYS_F_CONNECT, ERR_R_MALLOC_FAILURE);
    return NULL;
  }
  
  /* We first need to establish what sort of */
  /* connection we know how to make. We can use one of */
  /* SSLv23_client_method(), SSLv2_client_method() and */
  /* SSLv3_client_method(). */
  /*  Try to create a new SSL context. */
  if((e->ctx = SSL_CTX_new(SSLv23_client_method())) == NULL)
  {
    essl_update_errno();
    free(e);
    return NULL;
  }

  /* Set it up so tha we will connect to *any* site, regardless of their certificate. */
  SSL_CTX_set_verify(e->ctx, SSL_VERIFY_NONE, essl_socket_dumb_callback);
  /* Enable bug support hacks. */
  SSL_CTX_set_options(e->ctx, SSL_OP_ALL);

  /* Create new SSL connection state object. */
  e->ssl = SSL_new(e->ctx);
  if(e->ssl == NULL)
  {
    essl_update_errno();
    SSL_CTX_free(e->ctx);
    free(e);
    return NULL;
  }
  
  /* Attach the SSL session. */
  SSL_set_fd(e->ssl, fd);
  /* Connect using the SSL session. */
  if(SSL_connect(e->ssl) != 1)
  {
    essl_update_errno();
    if(essl_errno == 0) essl_errno = ERR_PACK(ERR_LIB_SYS, SYS_F_CONNECT, ERR_R_SYS_LIB);
    SSL_shutdown(e->ssl);
    SSL_free(e->ssl);
    SSL_CTX_free(e->ctx);
    free(e);
    return NULL;
  }
  return e;
}

/**
 * @brief Bind an user socket fd to the SSL context.
 * @param[in] fd The user FD to bind.
 * @param[in] cert The certificate file to use.
 * @param[in] private_key The private key file.
 * @return NULL on error, otherwise the SSL context.
 */
essl_socket_t essl_socket_accept(int fd, const struct essl_socket_cert_s cert, const struct essl_socket_cert_s private_key)
{
  struct essl_socket_s* e = NULL;
  essl_errno = 0ULL;
  if((e = malloc(sizeof(struct essl_socket_s))) == NULL)
  {
    essl_errno = ERR_PACK(ERR_LIB_USER, SYS_F_ACCEPT, ERR_R_MALLOC_FAILURE);
    return NULL;
  }
  
  /* We first need to establish what sort of */
  /* connection we know how to make. We can use one of */
  /* SSLv23_method(), SSLv2_method() and */
  /* SSLv3_method(). */
  /*  Try to create a new SSL context. */
  if((e->ctx = SSL_CTX_new(SSLv23_method())) == NULL)
  {
    essl_update_errno();
    free(e);
    return NULL;
  }
  /* Prevent small subgroup attacks */
  SSL_CTX_set_options(e->ctx, SSL_OP_SINGLE_DH_USE);
  /* Force openssl to use the user certs */ 
  if (SSL_CTX_load_verify_locations(e->ctx, cert.path, private_key.path) != 1)
  {
    essl_update_errno();
    SSL_CTX_free(e->ctx);
    free(e);
    return NULL;
  }
  if (SSL_CTX_set_default_verify_paths(e->ctx) != 1)
  {
    essl_update_errno();
    SSL_CTX_free(e->ctx);
    free(e);
    return NULL;
  }
  
  /* Use the proper cert file */
  if(SSL_CTX_use_certificate_file(e->ctx, cert.path, cert.type == ESSL_SOCKET_CERT_TYPE_ASN1 ? SSL_FILETYPE_ASN1 : SSL_FILETYPE_PEM) <= 0)
  {
    essl_update_errno();
    SSL_CTX_free(e->ctx);
    free(e);
    return NULL;
  }
  
  /* Use the proper private key file */
  if(SSL_CTX_use_PrivateKey_file(e->ctx, private_key.path, private_key.type == ESSL_SOCKET_CERT_TYPE_ASN1 ? SSL_FILETYPE_ASN1 : SSL_FILETYPE_PEM) <= 0)
  {
    essl_update_errno();
    SSL_CTX_free(e->ctx);
    free(e);
    return NULL;
  }
  
  /* verify private key */
  if (!SSL_CTX_check_private_key(e->ctx))
  {
    essl_update_errno();
    SSL_CTX_free(e->ctx);
    free(e);
    return NULL;
  }

  /* Create new SSL connection state object. */
  e->ssl = SSL_new(e->ctx);
  if(e->ssl == NULL)
  {
    essl_update_errno();
    SSL_CTX_free(e->ctx);
    free(e);
    return NULL;
  }
  
  /* Attach the SSL session. */
  SSL_set_fd(e->ssl, fd);
  
  /* Connect using the SSL session. */
  if(SSL_accept(e->ssl) != 1)
  {
    essl_update_errno();
    if(essl_errno == 0)
      essl_errno = ERR_PACK(ERR_LIB_SYS, SYS_F_ACCEPT, ERR_R_SYS_LIB);
    SSL_shutdown(e->ssl);
    SSL_free(e->ssl);
    SSL_CTX_free(e->ctx);
    free(e);
    return NULL;
  }
  
  return e;
}

/**
 * @brief Write a buffer into the specified ssl connection.
 * @param[in] essl The SSL context.
 * @param[in] buffer The buffer to write.
 * @param[in] length The buffer length.
 * @return 
 * >0 The write operation was successful, the return value is the number of bytes actually written to the TLS/SSL connection.
 * =0 The write operation was not successful. Probably the underlying connection was closed. Call SSL_get_error() with the return value ret to find out, whether an error occurred or the connection was shut down cleanly (SSL_ERROR_ZERO_RETURN).
 * <0 The write operation was not successful, because either an error occurred or action must be taken by the calling process. See essl_errno to find out the reason.
 */
int essl_socket_write(essl_socket_t essl, const void* buffer, size_t length)
{
  int r;
  essl_errno = 0ULL;
  struct essl_socket_s* e = (struct essl_socket_s*)essl;
  if(!e)
  {
    essl_errno = ERR_PACK(ERR_LIB_USER, SYS_F_FFLUSH, ERR_R_PASSED_NULL_PARAMETER);
    return -1;
  }
  r = SSL_write(e->ssl, buffer, length);
  if(r < 0) essl_errno = r;
  return r;
}

/**
 * @brief Read a buffer from the specified ssl connection.
 * @param[in] essl The SSL context.
 * @param[out] buffer The buffer to read.
 * @param[in] length The buffer length.
 * @return 
 * >0 The read operation was successful; the return value is the number of bytes actually read from the TLS/SSL connection.
 * =0 The read operation was not successful. The reason may either be a clean shutdown due to a "close notify" alert sent by the peer (in which case the SSL_RECEIVED_SHUTDOWN flag in the ssl shutdown state is set (see SSL_shutdown, SSL_set_shutdown). It is also possible, that the peer simply shut down the underlying transport and the shutdown is incomplete. Call SSL_get_error() with the return value ret to find out, whether an error occurred or the connection was shut down cleanly (SSL_ERROR_ZERO_RETURN).
 * <0 The read operation was not successful, because either an error occurred or action must be taken by the calling process. See essl_errno to find out the reason.
 */
int essl_socket_read(essl_socket_t essl, void* buffer, size_t length)
{
  int r;
  essl_errno = 0ULL;
  struct essl_socket_s* e = (struct essl_socket_s*)essl;
  if(!e) {
    essl_errno = ERR_PACK(ERR_LIB_USER, SYS_F_FREAD, ERR_R_PASSED_NULL_PARAMETER);
    return -1;
  }
  r = SSL_read(e->ssl, buffer, length);
  if(r < 0) essl_errno = r;
  return r;
}
#endif /* ESSL_SUPPORT_SOCKET */

/*****************************************************
 *     _____  ___________ _________ 
 *    /  _  \ \_   _____//   _____/ 
 *   /  /_\  \ |    __)_ \_____  \  
 *  /    |    \|        \/        \ 
 *  \____|__  /_______  /_______  / 
 *          \/        \/        \/  
 *****************************************************/
#ifdef ESSL_SUPPORT_AES

struct essl_aes_s
{
    EVP_CIPHER_CTX* encrypt;
    EVP_CIPHER_CTX* decrypt;
};

/**
 * @brief Creates a 256-bit key and an IV using the key data provided.
 * @param[in] key_data Buffer containing data bytes that is used to derive the key data.
 * @param[in] key_data_len The buffer length.
 * @param[in] salt Used as a salt in the derivation: it should point to an 8 byte buffer or NULL if no salt is used.
 * @param[in] count The iteration count to use. A higher value is more secure but slower. (see ESSL_AES_COUNT)
 * @return NULL on error, otherwise the context.
 */
essl_aes_t essl_aes_initialize(const uint8_t* key_data, size_t key_data_len, const uint8_t* salt, int count)
{
  struct essl_aes_s* ctx;
  int i;
  uint8_t key[ESSL_AES_KEY_LEN];
  uint8_t iv[ESSL_AES_KEY_LEN];
  
  essl_errno = 0ULL;
  if((ctx = malloc(sizeof(struct essl_aes_s))) == NULL)
  {
    essl_errno = ERR_PACK(ERR_LIB_USER, 0, ERR_R_MALLOC_FAILURE);
    return NULL;
  }
  /* Generate the key and the IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key. */
  i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, count, key, iv);
  if (i != ESSL_AES_KEY_LEN)
  {
    essl_update_errno();
    if(essl_errno == 0) essl_errno = ERR_PACK(ERR_LIB_SYS, 0, ERR_R_EVP_LIB);
    free(ctx);
    return NULL;
  }

  if((ctx->encrypt = EVP_CIPHER_CTX_new()) == NULL)
  {
    essl_update_errno();
    if(essl_errno == 0) essl_errno = ERR_PACK(ERR_LIB_SYS, 0, ERR_R_EVP_LIB);
    free(ctx);
    return NULL;
  }
  if((ctx->decrypt = EVP_CIPHER_CTX_new()) == NULL)
  {
    essl_update_errno();
    if(essl_errno == 0) essl_errno = ERR_PACK(ERR_LIB_SYS, 0, ERR_R_EVP_LIB);
    EVP_CIPHER_CTX_free(ctx->encrypt);
    free(ctx);
    return NULL;
  }
    
  EVP_CIPHER_CTX_init(ctx->encrypt);
  EVP_EncryptInit_ex(ctx->encrypt, EVP_aes_256_cbc(), NULL, key, iv);
  EVP_CIPHER_CTX_init(ctx->decrypt);
  EVP_DecryptInit_ex(ctx->decrypt, EVP_aes_256_cbc(), NULL, key, iv);

  return ctx;
}

/**
 * @brief Release of resources allocated by the essl_aes_initialize function.
 * @param[out] context The AES context.
 * @param[out] enc_ctx Context used for encryption.
 * @param[out] dec_ctx Context used for decryption.*
 */
void essl_aes_release(essl_aes_t context)
{
  struct essl_aes_s* ctx = (struct essl_aes_s*)context;
  essl_errno = 0ULL;
  if(ctx == NULL)
  {
    essl_errno = ERR_PACK(ERR_LIB_USER, 0, ERR_R_OPERATION_FAIL);
    return;
  }
  if(ctx->encrypt != NULL)
  {
    EVP_CIPHER_CTX_cleanup(ctx->encrypt);
    EVP_CIPHER_CTX_free(ctx->encrypt);
    ctx->encrypt = NULL;
  }
  if(ctx->decrypt != NULL)
  {
    EVP_CIPHER_CTX_cleanup(ctx->decrypt);
    EVP_CIPHER_CTX_free(ctx->decrypt);
    ctx->decrypt = NULL;
  }
  free(ctx);
}

/**
 * @brief Encryption of the text pointed by 'plain_text'.
 * @param[in] context The AES context.
 * @param[in] enc_ctx Context used for encryption.
 * @param[in] plaintext The plaintext to encrypt.
 * @param[out] len The size of the text, this size will be updated at the output of the function, this update will correspond to the size of the output buffer.
 * @return Returns the encrypted buffer (WARNING: a malloc is done on this buffer, the user must free it), otherwise NULL.
 */
uint8_t* essl_aes_encrypt(essl_aes_t context, const uint8_t* plaintext, size_t* len)
{
  struct essl_aes_s* ctx = (struct essl_aes_s*)context;
  essl_errno = 0ULL;
  if(ctx == NULL || ctx->encrypt == NULL)
  {
    essl_errno = ERR_PACK(ERR_LIB_USER, 0, ERR_R_OPERATION_FAIL);
    return NULL;
  }
  /* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
  size_t cipher_len = *len + AES_BLOCK_SIZE;
  size_t final_len = 0;
  uint8_t* ciphertext = malloc(cipher_len);
  if(ciphertext == NULL)
  {
    essl_errno = ERR_PACK(ERR_LIB_USER, 0, ERR_R_MALLOC_FAILURE);
    return NULL;
  }
  /* Allows the reuse of "enc_ctx" for multiple encryption cycles. */
  EVP_EncryptInit_ex(ctx->encrypt, NULL, NULL, NULL, NULL);

  /* Cipher text update, cipher_len is filled with the length of the generated cipher text, len is the plaintext size in bytes. */
  EVP_EncryptUpdate(ctx->encrypt, ciphertext, (int*)&cipher_len, plaintext, *len);

  /* Updates the cipher text with the last remaining bytes. */
  EVP_EncryptFinal_ex(ctx->encrypt, ciphertext + cipher_len, (int*)&final_len);
  /* Update of the new size of the encrypted buffer. */
  *len = cipher_len + final_len;
  return ciphertext;
}

/**
 * @brief Decryption of the text pointed by 'cipher_text'.
 * @param[in] context The AES context.
 * @param[in] dec_ctx Context used for decryption.
 * @param[in] ciphertext The cipher text to decrypt.
 * @param[out] len The size of the text, this size will be updated at the output of the function, this update will correspond to the size of the output buffer.
 * @return Returns the plaintext buffer (WARNING: a malloc is done on this buffer, the user must free it), otherwise NULL.
 */
uint8_t* essl_aes_decrypt(essl_aes_t context, const uint8_t* ciphertext, size_t* len)
{
  struct essl_aes_s* ctx = (struct essl_aes_s*)context;
  essl_errno = 0ULL;
  if(ctx == NULL || ctx->decrypt == NULL)
  {
    essl_errno = ERR_PACK(ERR_LIB_USER, 0, ERR_R_OPERATION_FAIL);
    return NULL;
  }
  /* The plaintext will always be equal to or less than the length of the cipher text. */
  size_t plain_len = *len;
  size_t final_len = 0;
  uint8_t* plaintext = malloc(plain_len);
  
  if(plaintext == NULL)
  {
    essl_errno = ERR_PACK(ERR_LIB_USER, 0, ERR_R_MALLOC_FAILURE);
    return NULL;
  }
  /* Allows the reuse of "dec_ctx" for multiple decryption cycles. */
  EVP_DecryptInit_ex(ctx->decrypt, NULL, NULL, NULL, NULL);
  /* Plaintext update, plain_len is filled with the length of the generated plaintext, len is the cipher text size in bytes. */
  EVP_DecryptUpdate(ctx->decrypt, plaintext, (int*)&plain_len, ciphertext, *len);
  /* Updates the plain text with the last remaining bytes. */
  EVP_DecryptFinal_ex(ctx->decrypt, plaintext+plain_len, (int*)&final_len);

  /* Update of the new size of the decrypted buffer. */
  *len = plain_len + final_len;
  return plaintext;
}

#endif /* ESSL_SUPPORT_AES */

