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
  #include <stdint.h>
  #include <errno.h>
  #include <openssl/opensslconf.h>

  /*****************************************************
   * _______________________________ ________ __________ 
   * \_   _____/\______   \______   \\_____  \\______   \
   *  |    __)_  |       _/|       _/ /   |   \|       _/
   *  |        \ |    |   \|    |   \/    |    \    |   \
   * /_______  / |____|_  /|____|_  /\_______  /____|_  /
   *         \/         \/        \/         \/       \/        
   *****************************************************/

#ifndef OPENSSL_NO_ERR
  #define ESSL_SUPPORT_ERROR
#endif /* OPENSSL_NO_ERR */
  
  extern uint64_t essl_errno;
  /**
   * @brief Get the string representation of the essl_errno value in a static buffer.
   * @return NULL if ESSL_SUPPORT_ERROR is not defined otherwise the string error.
   */
  const char* essl_strerror(void);

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

  #define ESSL_SUPPORT_MD2
  
  /**
   * @brief The Hexa string length.
   */
  #define ESSL_MD2_STRING_LENGTH 33

  /**
   * @brief The length of the md2 digest.
   */
  #define ESSL_MD2_DIGEST_LENGTH MD2_DIGEST_LENGTH

  /**
   * @brief MD2 digest type.
   */
  typedef uint8_t essl_md2_digest_t[ESSL_MD2_DIGEST_LENGTH];

  /**
   * @brief MD2 hexa string type.
   */
  typedef char essl_md2_string_t [ESSL_MD2_STRING_LENGTH];

  /**
   * @brief Generate a MD2 digest
   * @param[in] str String to hash
   * @param[in] length String length to hash
   * @param[out] result Output hash
   */
  void essl_md2_do_hash(const char* str, size_t length, essl_md2_digest_t result);

  /**
   * @brief Convert a MD2 hash to hexa string.
   * @param[in] digest MD2 hash
   * @param[out] str Output string.
   */
  void essl_md2_digest_to_string(essl_md2_digest_t digest, essl_md2_string_t str);

  /**
   * @brief Generate a MD2 digest of a file
   * @param[in] filename The file to hash
   * @param[out] result Output hash
   * @return -1 on error, otherwise 0 (see errno for more details).
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

  #define ESSL_SUPPORT_MD4
  
  /**
   * @brief The Hexa string length.
   */
  #define ESSL_MD4_STRING_LENGTH 33

  /**
   * @brief The length of the md5 digest.
   */
  #define ESSL_MD4_DIGEST_LENGTH MD4_DIGEST_LENGTH

  /**
   * @brief MD4 digest type.
   */
  typedef uint8_t essl_md4_digest_t[ESSL_MD4_DIGEST_LENGTH];

  /**
   * @brief MD4 hexa string type.
   */
  typedef char essl_md4_string_t [ESSL_MD4_STRING_LENGTH];

  /**
   * @brief Generate a MD4 digest
   * @param[in] str String to hash
   * @param[in] length String length to hash
   * @param[out] result Output hash
   */
  void essl_md4_do_hash(const char* str, size_t length, essl_md4_digest_t result);

  /**
   * @brief Convert a MD4 hash to hexa string.
   * @param[in] digest MD4 hash
   * @param[out] str Output string.
   */
  void essl_md4_digest_to_string(essl_md4_digest_t digest, essl_md4_string_t str);

  /**
   * @brief Generate a MD4 digest of a file
   * @param[in] filename The file to hash
   * @param[out] result Output hash
   * @return -1 on error, otherwise 0 (see errno for more details).
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

  #define ESSL_SUPPORT_MD5

  /**
   * @brief The Hexa string length.
   */
  #define ESSL_MD5_STRING_LENGTH 33

  /**
   * @brief The length of the md5 digest.
   */
  #define ESSL_MD5_DIGEST_LENGTH MD5_DIGEST_LENGTH

  /**
   * @brief MD5 digest type.
   */
  typedef uint8_t essl_md5_digest_t[ESSL_MD5_DIGEST_LENGTH];

  /**
   * @brief MD5 hexa string type.
   */
  typedef char essl_md5_string_t [ESSL_MD5_STRING_LENGTH];

  /**
   * @brief Generate a MD5 digest
   * @param[in] str String to hash
   * @param[in] length String length to hash
   * @param[out] result Output hash
   */
  void essl_md5_do_hash(const char* str, size_t length, essl_md5_digest_t result);

  /**
   * @brief Convert a MD5 hash to hexa string.
   * @param[in] digest MD5 hash
   * @param[out] str Output string.
   */
  void essl_md5_digest_to_string(essl_md5_digest_t digest, essl_md5_string_t str);

  /**
   * @brief Generate a MD5 digest of a file
   * @param[in] filename The file to hash
   * @param[out] result Output hash
   * @return -1 on error, otherwise 0 (see errno for more details).
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

  #define ESSL_SUPPORT_BASE64
  
  /**
   * @brief Encode a paln text to a base64 representation.
   * @param[in] input The plain text to encode.
   * @param[in] ilength The plain text length.
   * @param[out] output The encoded message in base64 (free required)
   * @param[out] olength The encoded message length.
   * @return -1 on error, otherwise 0 (see errno for more details).
   */ 
  int essl_base64_encode(const char* input, const size_t ilength, char** output, size_t* olength);
 
  /**
   * @brief Decode a base64 message to a plain text.
   * @param[in] input The message in base64.
   * @param[in] ilength  The length of the base64 message.
   * @param[out] output The plain text message (free required).
   * @param[out] olength The decoded message length.
   * @return -1 on error, otherwise 0 (see errno for more details).
   */ 
  int essl_base64_decode(const char* input, const size_t ilength, char** output, size_t* olength);

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

  #define ESSL_SUPPORT_SHA1
  
  /**
   * @brief The length of the SHA digest.
   */
  #define ESSL_SHA_DIGEST_LENGTH SHA_DIGEST_LENGTH

  /**
   * @brief Length of the SHA1 digest.
   */
  #define ESSL_SHA_HEX_DIGEST_LENGTH (ESSL_SHA_DIGEST_LENGTH*2)

  /**
   * @brief Length of the SHA1 digest.
   */
  typedef char essl_sha1_string_t[ESSL_SHA_HEX_DIGEST_LENGTH + 1];

  /**
   * @brief Calculate a SHA1 for a specified string.
   * @param[in] input The plain text to encode.
   * @param[in] ilength The plain text length.
   * @param[out] output The encoded output string.
   * @return -1 on error, otherwise 0 (see errno for more details).
   */
  int essl_sha1_do_hash(const char* input, size_t ilength, essl_sha1_string_t output);

  /**
   * @brief Calculate a SHA1 for a specified file.
   * @param[in] filename The file name.
   * @param[out] output The output buffer with the sha1.
   * @return -1 on error, otherwise 0 (see errno for more details).
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

  #define ESSL_SUPPORT_SOCKET
  
  /**
   * @brief Socket context.
   */
  typedef void* essl_socket_t;
  
  
  /**
   * @brief Enum used to define the specified file type.
   */
  typedef enum
  { 
    ESSL_SOCKET_CERT_TYPE_ASN1 = 0, /**< File type ASN1 */
    ESSL_SOCKET_CERT_TYPE_PEM  = 1  /**< File type PEM */
  } essl_socket_cert_type_et;
  
  /**
   * @brief Specifying the certificate to use for the server part.
   */
  struct essl_socket_cert_s
  {
    essl_socket_cert_type_et type; /**< The file type. */
    char* path; /**< The file path. */
  };
  
  
  /**
   * @brief Initialize the SSL stack, should be called only once in your application.
   * @return -1 if the initialization fail, otherwise 0.
   */
  int essl_socket_initialize(void);
  
  /**
   * @brief Release the SSL stack, should be called only once in your application.
   */
  void essl_socket_release(void);
  
  /**
   * @brief Bind an suer socket fd to the SSL context.
   * @param[in] fd The user FD to bind.
   * @return NULL on error, otherwise the SSL context.
   */
  essl_socket_t essl_socket_connect(int fd);

  /**
   * @brief Bind an user socket fd to the SSL context.
   * @param[in] fd The user FD to bind.
   * @param[in] cert The certificate file to use.
   * @param[in] private_key The private key file.
   * @return NULL on error, otherwise the SSL context.
   */
  essl_socket_t essl_socket_accept(int fd, const struct essl_socket_cert_s cert, const struct essl_socket_cert_s private_key);

  /**
   * @brief Close the resources allocated by the connect/accept function (does not close the user FD).
   * @param[in,out] essl The context to close.
   */
  void essl_socket_close(essl_socket_t essl);
  
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
  int essl_socket_write(essl_socket_t essl, const void* buffer, size_t length);

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
  int essl_socket_read(essl_socket_t essl, void* buffer, size_t length);
  
#endif /* OPENSSL_NO_SSL2 && OPENSSL_NO_BIO */

  /*****************************************************
   *     _____  ___________ _________ 
   *    /  _  \ \_   _____//   _____/ 
   *   /  /_\  \ |    __)_ \_____  \  
   *  /    |    \|        \/        \ 
   *  \____|__  /_______  /_______  / 
   *          \/        \/        \/  
   *****************************************************/
#ifndef EVP_MD

  #define ESSL_SUPPORT_AES

  /**
   * @brief The iteration count to use.
   */
  #define ESSL_AES_COUNT 5
  
  /**
   * @brief The default key length.
   */
  #define ESSL_AES_KEY_LEN 32
  
  /**
   * @typedef essl_aes_t
   * @brief AES context.
   */
  typedef void* essl_aes_t;

  
  /**
   * @brief Creates a 256-bit key and an IV using the key data provided.
   * @param[in] key_data Buffer containing data bytes that is used to derive the key data.
   * @param[in] key_data_len The buffer length.
   * @param[in] salt Used as a salt in the derivation: it should point to an 8 byte buffer or NULL if no salt is used.
   * @param[in] count The iteration count to use. A higher value is more secure but slower. (see ESSL_AES_COUNT)
   * @return NULL on error, otherwise the context.
   */
  essl_aes_t essl_aes_initialize(const uint8_t* key_data, size_t key_data_len, const uint8_t* salt, int count);

  /**
   * @brief Release of resources allocated by the essl_aes_initialize function.
   * @param[out] context The AES context.
   */
  void essl_aes_release(essl_aes_t context);

  /**
   * @brief Encryption of the text pointed by 'plain_text'.
   * @param[in] context The AES context.
   * @param[in] plaintext The plaintext to encrypt.
   * @param[out] len The size of the text, this size will be updated at the output of the function, this update will correspond to the size of the output buffer.
   * @return Returns the encrypted buffer (WARNING: a malloc is done on this buffer, the user must free it), otherwise NULL.
   */
  uint8_t* essl_aes_encrypt(essl_aes_t context, const uint8_t* plaintext, size_t* len);

  /**
   * @brief Decryption of the text pointed by 'cipher_text'.
   * @param[in] context The AES context.
   * @param[in] ciphertext The cipher text to decrypt.
   * @param[out] len The size of the text, this size will be updated at the output of the function, this update will correspond to the size of the output buffer.
   * @return Returns the plaintext buffer (WARNING: a malloc is done on this buffer, the user must free it), otherwise NULL.
   */
  uint8_t* essl_aes_decrypt(essl_aes_t context, const uint8_t* ciphertext, size_t* len);
#endif /* EVP_MD */
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __ESSL_H__ */
