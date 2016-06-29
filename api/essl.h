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
#ifndef OPENSSL_NO_MD4
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
#endif /* OPENSSL_NO_MD4 */


  /*****************************************************
   *    _____  ________   .________
   *   /     \ \______ \  |   ____/
   *  /  \ /  \ |    |  \ |____  \
   * /    Y    \|    `   \/       \
   * \____|__  /_______  /______  /
   *         \/        \/       \/                                  
   *****************************************************/
#ifndef OPENSSL_NO_MD5
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
#endif /* OPENSSL_NO_SHA1 */


  /*****************************************************
   *   _________________  _________  ____  __.______________________
   *  /   _____/\_____  \ \_   ___ \|    |/ _|\_   _____/\__    ___/
   *  \_____  \  /   |   \/    \  \/|      <   |    __)_   |    |
   *  /        \/    |    \     \___|    |  \  |        \  |    |
   * /_______  /\_______  /\______  /____|__ \/_______  /  |____|
   *         \/         \/        \/        \/        \/
   *****************************************************/
#if !defined(OPENSSL_NO_SSL2) && !defined(OPENSSL_NO_BIO)

  extern unsigned long essl_errno;
  
  /**
   * @typedef essl_socket_t
   * @brief Socket context.
   */
  typedef void* essl_socket_t;
  
  /**
   * @fn int essl_initialize_ssl(void)
   * @brief Initialize the SSL stack, should be called only once in your application.
   * @return -1 if the initialization fail, 0 else.
   */
  int essl_initialize_ssl(void);
  
  /**
   * @fn void essl_initialize_ssl(void)
   * @brief Release the SSL stack, should be called only once in your application.
   */
  void essl_release_ssl(void);
  
  /**
   * @fn const char* essl_strerror_ssl(void)
   * @brief Get the string representation of the essl_errno value in a static buffer.
   * @return NULL if OPENSSL_NO_ERR is defined else the string error.
   */
  const char* essl_strerror_ssl(void);
  
  /**
   * @fn essl_socket_t essl_connect_ssl(int fd)
   * @brief Bind an suer socket fd to the SSL context.
  * @param fd The user FD to bind.
   * @return NULL on error, else the SSL context.
   */
  essl_socket_t essl_connect_ssl(int fd);

  /**
   * @fn essl_socket_t essl_accept_ssl(int fd)
   * @brief Bind an user socket fd to the SSL context.
   * @param fd The user FD to bind.
   * @return NULL on error, else the SSL context.
   */
  essl_socket_t essl_accept_ssl(int fd);

  /**
   * @fn void essl_close_ssl(essl_socket_t essl)
   * @brief Close the resources allocated by the connect/accept function (does not close the user FD).
   * @param essl The context to close.
   */
  void essl_close_ssl(essl_socket_t essl);
  
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
  int essl_write_ssl(essl_socket_t essl, const void* buffer, size_t length);

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
  int essl_read_ssl(essl_socket_t essl, void* buffer, size_t length);
  
#endif /* OPENSSL_NO_SSL2 && OPENSSL_NO_BIO */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __ESSL_H__ */
