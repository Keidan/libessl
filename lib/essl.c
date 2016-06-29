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
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>

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
