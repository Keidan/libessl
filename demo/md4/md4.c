#include <essl.h>
#include <stdio.h>
#include <stdlib.h>

#define EXIT_NOT_SUPPORTED 2

#define FOO_MDS "0ac6700c491d70fb8650940b1ca1e4b2"

int main(int argc, char** argv)
{
  (void)argc;/* remove warning */
  (void)argv;/* remove warning */

#ifdef ESSL_SUPPORT_MD4
  const char* str = "foo";
  essl_md4_digest_t res;
  essl_md4_string_t mds;

  essl_md4_do_hash(str, strlen(str), res);
  essl_md4_digest_to_string(res, mds);
  printf("%s: '%s'\n", str, mds);
  return strcmp(mds, FOO_MDS) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
#else
  printf("MD4 not supported\n");
  return EXIT_NOT_SUPPORTED;
#endif /* ESSL_SUPPORT_MD4 */
}
