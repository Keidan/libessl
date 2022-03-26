#include <essl.h>
#include <stdio.h>
#include <stdlib.h>

#define EXIT_NOT_SUPPORTED 2

#define FOO_MDS "d11f8ce29210b4b50c5e67533b699d02"

int main(int argc, char** argv)
{
  (void)argc;/* remove warning */
  (void)argv;/* remove warning */

#ifdef ESSL_SUPPORT_MD2
  const char* str = "foo";
  essl_md2_digest_t res;
  essl_md2_string_t mds;

  essl_md2_do_hash(str, strlen(str), res);
  essl_md2_digest_to_string(res, mds);
  printf("%s: '%s'\n", str, mds);
  return strcmp(mds, FOO_MDS) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
#else
  printf("MD2 not supported\n");
  return EXIT_NOT_SUPPORTED;
#endif /* ESSL_SUPPORT_MD2 */
}

