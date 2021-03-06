#include <essl.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {

#ifndef OPENSSL_NO_MD5
  const char* str = "Hello world";
  essl_md5_digest_t res;
  essl_md5_string_t mds;

  (void)argc;/* remove warning */
  (void)argv;/* remove warning */

  essl_md5_do_hash(str, strlen(str), res);
  printf("%s: '%s'\n", str, res);


  essl_md5_digest_to_string(res, mds);
  printf("%s: '%s'\n", str, mds);
#else
  printf("MD5 not supported\n");
#endif /* OPENSSL_NO_MD5 */

  return 0;
}
