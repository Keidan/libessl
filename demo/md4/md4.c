#include <essl.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv)
{
  (void)argc;/* remove warning */
  (void)argv;/* remove warning */

#ifdef ESSL_SUPPORT_MD4
  const char* str = "Hello world";
  essl_md4_digest_t res;
  essl_md4_string_t mds;

  essl_md4_do_hash(str, strlen(str), res);
  printf("%s: '%s'\n", str, res);


  essl_md4_digest_to_string(res, mds);
  printf("%s: '%s'\n", str, mds);
#else
  printf("MD4 not supported\n");
#endif /* ESSL_SUPPORT_MD4 */

  return 0;
}
