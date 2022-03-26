#include <essl.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv)
{
  (void)argc;/* remove warning */
  (void)argv;/* remove warning */
#ifndef OPENSSL_NO_AES
  essl_aes_t ctx;
  

  uint32_t salt[] = {98765, 24560};
  uint8_t* key_data;
  int key_data_len, i;
  char* texts[] = {
    "azerty",
    "qwerty",
    "Lorem ipsum dolor sit amet",
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit.\nQuisque luctus justo eu dui venenatis, ut imperdiet nibh ornare.\nDonec vestibulum, nulla in bibendum laoreet, tortor sapien pharetra lectus, nec blandit mauris libero in sem.\n",
    NULL
  };

  /* the key_data is read from the argument list */
  const char* the_key = "It's my beautiful key";
  key_data = (uint8_t *)the_key;
  key_data_len = strlen(the_key);
  
  /* gen key and iv. init the cipher ctx object */
  if ((ctx = essl_aes_initialize(key_data, key_data_len, (uint8_t *)&salt, ESSL_AES_COUNT)) == NULL)
  {
    printf("Couldn't initialize AES cipher\n");
    return -1;
  }

  /* encrypt and decrypt each texts string and compare with the original */
  for (i = 0; texts[i]; i++)
  {
    char *plaintext;
    uint8_t *ciphertext;
    size_t olen, len;
    
    olen = len = strlen(texts[i]) + 1;
    
    ciphertext = essl_aes_encrypt(ctx, (const uint8_t*)texts[i], &len);
    plaintext = (char *)essl_aes_decrypt(ctx, ciphertext, &len);

    if (strncmp(plaintext, texts[i], olen) != 0) 
      printf("Encrypt/Decrypt ERROR for \"%s\"\n", texts[i]);
    else 
      printf("Encrypt/Decrypt SUCCESS for \"%s\"\n", plaintext);
    
    free(ciphertext);
    free(plaintext);
  }
  essl_aes_release(ctx);
#else
  printf("AES not supported\n");
#endif /* OPENSSL_NO_AES */
  return 0;
}
