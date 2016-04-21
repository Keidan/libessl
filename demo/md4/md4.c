#include <essl.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {

  const char* str = "Hello world";
  essl_md4_digest_t res;
  essl_md4_string_t mds;

  (void)argc;/* remove warning */
  (void)argv;/* remove warning */

  essl_md4_do_hash(str, strlen(str), res);
  printf("%s: '%s'\n", str, res);


  essl_md4_digest_to_string(res, mds);
  printf("%s: '%s'\n", str, mds);

  return 0;
}
