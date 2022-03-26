#include <essl.h>
#include <stdio.h>
#include <stdlib.h>

#define EXIT_NOT_SUPPORTED 2

#define FOO_MDS "acbd18db4cc2f85cedef654fccc4a4d8"

int main(int argc, char** argv)
{
  (void)argc;/* remove warning */
  (void)argv;/* remove warning */

#ifdef ESSL_SUPPORT_MD5
  const char* str = "foo";
  essl_md5_digest_t res;
  essl_md5_string_t mds;

  essl_md5_do_hash(str, strlen(str), res);
  essl_md5_digest_to_string(res, mds);
  printf("%s: '%s'\n", str, mds);
  return strcmp(mds, FOO_MDS) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
#else
  printf("MD5 not supported\n");
  return EXIT_NOT_SUPPORTED;
#endif /* ESSL_SUPPORT_MD5 */
}
