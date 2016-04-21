/**
*******************************************************************************
* @file essl.h
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
#ifndef __ESSL_H__
#define __ESSL_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

  #include <string.h>
  #include <errno.h>
  #include <openssl/opensslconf.h>


  /*****************************************************
   *    _____  ________   ________  
   *   /     \ \______ \  \_____  \
   *  /  \ /  \ |    |  \  /  ____/ 
   * /    Y    \|    `   \/       \
   * \____|__  /_______  /\_______ \
   *         \/        \/         \/                               
   *****************************************************/
#ifndef OPENSSL_NO_MD2
  #include <openssl/md2.h>
  /**
   * @def ESSL_MD2_STRING_LENGTH
   * @brief The Hexa string length.
   */
  #define ESSL_MD2_STRING_LENGTH 33

  /**
   * @def ESSL_MD2_DIGEST_LENGTH
   * @brief The length of the md2 digest.
   */
  #define ESSL_MD2_DIGEST_LENGTH MD2_DIGEST_LENGTH

  /**
   * @typedef essl_md2_digest_t
   * @brief MD2 digest type.
   */
  typedef unsigned char essl_md2_digest_t[ESSL_MD2_DIGEST_LENGTH];

  /**
   * @typedef essl_md2_string_t
   * @brief MD2 hexa string type.
   */
  typedef char essl_md2_string_t [ESSL_MD2_STRING_LENGTH];

  /**
   * @fn void essl_md2_do_hash(const char* str, size_t length, essl_md24_digest_t result) 
   * @brief Generate a MD2 digest
   * @param str String to hash
   * @param length String length to hash
   * @param result Output hash
   */
  void essl_md2_do_hash(const char* str, size_t length, essl_md2_digest_t result);

  /**
   * @fn void essl_md2_digest_to_string(essl_md2_digest_t digest, essl_md2_string_t str)
   * @brief Convert a MD2 hash to hexa string.
   * @param digest MD2 hash
   * @param str Output string.
   */
  void essl_md2_digest_to_string(essl_md2_digest_t digest, essl_md2_string_t str);

  /**
   * @fn void essl_md2_do_hash_file(const char* filename, essl_md2_digest_t result) 
   * @brief Generate a MD2 digest of a file
   * @param filename The file to hash
   * @param result Output hash
   * @return -1 on error, 0 else (see errno for more details).
   */
  int essl_md2_do_hash_file(const char* filename, essl_md2_digest_t result);
#endif /* OPENSSL_NO_MD2 */

  /*****************************************************
   *    _____  ________      _____  
   *   /     \ \______ \    /  |  | 
   *  /  \ /  \ |    |  \  /   |  |_
   * /    Y    \|    `   \/    ^   /
   * \____|__  /_______  /\____   | 
   *         \/        \/      |__| 
   *****************************************************/
  #include <openssl/md4.h>

  /**
   * @def ESSL_MD4_STRING_LENGTH
   * @brief The Hexa string length.
   */
  #define ESSL_MD4_STRING_LENGTH 33

  /**
   * @def ESSL_MD5_DIGEST_LENGTH
   * @brief The length of the md5 digest.
   */
  #define ESSL_MD4_DIGEST_LENGTH MD4_DIGEST_LENGTH

  /**
   * @typedef essl_md4_digest_t
   * @brief MD4 digest type.
   */
  typedef unsigned char essl_md4_digest_t[ESSL_MD4_DIGEST_LENGTH];

  /**
   * @typedef essl_md4_string_t
   * @brief MD4 hexa string type.
   */
  typedef char essl_md4_string_t [ESSL_MD4_STRING_LENGTH];

  /**
   * @fn void essl_md4_do_hash(const char* str, size_t length, essl_md4_digest_t result) 
   * @brief Generate a MD4 digest
   * @param str String to hash
   * @param length String length to hash
   * @param result Output hash
   */
  void essl_md4_do_hash(const char* str, size_t length, essl_md4_digest_t result);

  /**
   * @fn void essl_md4_digest_to_string(essl_md4_digest_t digest, essl_md4_string_t str)
   * @brief Convert a MD4 hash to hexa string.
   * @param digest MD4 hash
   * @param str Output string.
   */
  void essl_md4_digest_to_string(essl_md4_digest_t digest, essl_md4_string_t str);

  /**
   * @fn void essl_md4_do_hash_file(const char* filename, essl_md4_digest_t result) 
   * @brief Generate a MD4 digest of a file
   * @param filename The file to hash
   * @param result Output hash
   * @return -1 on error, 0 else (see errno for more details).
   */
  int essl_md4_do_hash_file(const char* filename, essl_md4_digest_t result);


  /*****************************************************
   *    _____  ________   .________
   *   /     \ \______ \  |   ____/
   *  /  \ /  \ |    |  \ |____  \
   * /    Y    \|    `   \/       \
   * \____|__  /_______  /______  /
   *         \/        \/       \/                                  
   *****************************************************/
  #include <openssl/md5.h>

  /**
   * @def ESSL_MD5_STRING_LENGTH
   * @brief The Hexa string length.
   */
  #define ESSL_MD5_STRING_LENGTH 33

  /**
   * @def ESSL_MD5_DIGEST_LENGTH
   * @brief The length of the md5 digest.
   */
  #define ESSL_MD5_DIGEST_LENGTH MD5_DIGEST_LENGTH

  /**
   * @typedef essl_md5_digest_t
   * @brief MD5 digest type.
   */
  typedef unsigned char essl_md5_digest_t[ESSL_MD5_DIGEST_LENGTH];

  /**
   * @typedef essl_md5_string_t
   * @brief MD5 hexa string type.
   */
  typedef char essl_md5_string_t [ESSL_MD5_STRING_LENGTH];

  /**
   * @fn void essl_md5_do_hash(const char* str, size_t length, essl_md5_digest_t result) 
   * @brief Generate a MD5 digest
   * @param str String to hash
   * @param length String length to hash
   * @param result Output hash
   */
  void essl_md5_do_hash(const char* str, size_t length, essl_md5_digest_t result);

  /**
   * @fn void essl_md5_digest_to_string(essl_md5_digest_t digest, essl_md5_string_t str)
   * @brief Convert a MD5 hash to hexa string.
   * @param digest MD5 hash
   * @param str Output string.
   */
  void essl_md5_digest_to_string(essl_md5_digest_t digest, essl_md5_string_t str);

  /**
   * @fn void essl_md5_do_hash_file(const char* filename, essl_md5_digest_t result) 
   * @brief Generate a MD5 digest of a file
   * @param filename The file to hash
   * @param result Output hash
   * @return -1 on error, 0 else (see errno for more details).
   */
  int essl_md5_do_hash_file(const char* filename, essl_md5_digest_t result);


  /*****************************************************
   * __________    _____    ____________________   ________   _____  
   * \______   \  /  _  \  /   _____/\_   _____/  /  _____/  /  |  | 
   *  |    |  _/ /  /_\  \ \_____  \  |    __)_  /   __  \  /   |  |_
   *  |    |   \/    |    \/        \ |        \ \  |__\  \/    ^   /
   *  |______  /\____|__  /_______  //_______  /  \_____  /\____   | 
   *         \/         \/        \/         \/         \/      |__| 
   *****************************************************/
  /**
   * @fn int essl_base64_encode(const char *input, const size_t ilength, char** output, size_t *olength)
   * @brief Encode a paln text to a base64 representation.
   * @param input The plain text to encode.
   * @param ilength The plain text length.
   * @param output The encoded message in base64 (free required)
   * @param olength The encoded message length.
   * @return -1 on error, 0 else (see errno for more details).
   */ 
  int essl_base64_encode(const char *input, const size_t ilength, char** output, size_t *olength);
 
  /**
   * @fn int essl_base64_decode(const char *input, const size_t ilength, char **output, size_t *olength)
   * @brief Decode a base64 message to a plain text.
   * @param input The message in base64.
   * @param ilength  The length of the base64 message.
   * @param output The plain text message (free required).
   * @param olength The decoded message length.
   * @return -1 on error, 0 else (see errno for more details).
   */ 
  int essl_base64_decode(const char *input, const size_t ilength, char **output, size_t *olength);

  /**
   * @fn size_t essl_base64_adjust_decode_length(const char *input, const size_t ilength)
   * @brief Get the length of the decoded message.
   * @param input The base64 buffer length
   * @param olength The encoded message length.
   * @return The decoded length of the base64 message.
   */
  size_t essl_base64_adjust_decode_length(const char *input, const size_t ilength);


  /*****************************************************
   *   _________ ___ ___    _____  ____ 
   *  /   _____//   |   \  /  _  \/_   |
   *  \_____  \/    ~    \/  /_\  \|   |
   *  /        \    Y    /    |    \   |
   * /_______  /\___|_  /\____|__  /___|
   *         \/       \/         \/     
   *****************************************************/
  #include <openssl/sha.h>
  /**
   * @def SHA_DIGEST_LENGTH
   * @brief The length of the SHA digest.
   */
  #define ESSL_SHA_DIGEST_LENGTH SHA_DIGEST_LENGTH

  /**
   **@def ESSL_SHA_HEX_DIGEST_LENGTH
   * @bieff Length of the SHA1 digest
   */
  #define ESSL_SHA_HEX_DIGEST_LENGTH (ESSL_SHA_DIGEST_LENGTH*2)

  /**
   **@typedef essl_sha1_string_t
   * @bieff Length of the SHA1 digest
   */
  typedef char essl_sha1_string_t[ESSL_SHA_HEX_DIGEST_LENGTH + 1];

  /**
   * @fn int essl_sha1_do_hash(const char* input, size_t ilength, essl_sha1_string_t output)
   * @brief Calculate a SHA1 for a specified string.
   * @param input The plain text to encode.
   * @param ilength The plain text length.
   * @param output The encoded output string.
   * @return -1 on error, 0 else (see errno for more details).
   */
  int essl_sha1_do_hash(const char* input, size_t ilength, essl_sha1_string_t output);

  /**
   * @fn int essl_sha1_do_hash_file(const char* filename, essl_sha1_string_t output)
   * @brief Calculate a SHA1 for a specified file.
   * @param filename The file name.
   * @param output The output buffer with the sha1.
   * @return -1 on error, 0 else (see errno for more details).
   */
  int essl_sha1_do_hash_file(const char* filename, essl_sha1_string_t output);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __ESSL_H__ */
