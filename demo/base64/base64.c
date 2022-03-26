#include <essl.h>
#include <stdio.h>
#include <stdlib.h>

#define EXIT_NOT_SUPPORTED 2

#define GCC_VERSION (__GNUC__ * 10000		\
		     + __GNUC_MINOR__ * 100	\
		     + __GNUC_PATCHLEVEL__)
#if GCC_VERSION > 40900 /* 4.9.0 */
#define PRINTF_SIZE_T "zu"
#else
#define PRINTF_SIZE_T "lu"
#endif


int main(int argc, char** argv)
{
  (void)argc;/* remove warning */
  (void)argv;/* remove warning */

#ifdef ESSL_SUPPORT_BASE64
  const char* str = "Hello world";
  char* output = NULL;
  char* output2 = NULL;
  size_t olength = 0;

  if(essl_base64_encode(str, strlen(str), &output, &olength) == 0)
    printf("%s: '%s' (%"PRINTF_SIZE_T")\n", str, output, olength);
  else fprintf(stderr, "Unable to base64 encode: (%d) %s\n", errno, strerror(errno));
  
  
  if(essl_base64_decode(output, olength, &output2, &olength) == 0)
    printf("%s: '%s' (%"PRINTF_SIZE_T")\n", output, output2, olength);
  else fprintf(stderr, "Unable to base64 decode: (%d) %s\n", errno, strerror(errno));

  int ret = strcmp(str, output2) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
  free(output2);
  free(output);
  return ret;
#else
  printf("Base64 not supported\n");
  return EXIT_NOT_SUPPORTED;
#endif /* ESSL_SUPPORT_BASE64 */
}
