#include <essl.h>
#include <stdio.h>
#include <stdlib.h>

#define GCC_VERSION (__GNUC__ * 10000 \
                               + __GNUC_MINOR__ * 100 \
                               + __GNUC_PATCHLEVEL__)
#if GCC_VERSION > 40900 /* 4.9.0 */
  #define PRINTF_SIZE_T "zu"
#else
  #define PRINTF_SIZE_T "lu"
#endif


int main(int argc, char** argv) {

  const char* str = "Hello world";
  char* output = NULL;
  char* output2 = NULL;
  size_t olength = 0;

  (void)argc;/* remove warning */
  (void)argv;/* remove warning */

  if(essl_base64_encode(str, strlen(str), &output, &olength) == 0)
    printf("%s: '%s' (%"PRINTF_SIZE_T")\n", str, output, olength);
  else fprintf(stderr, "Unable to base64 encode: (%d) %s\n", errno, strerror(errno));
  
  
  if(essl_base64_decode(output, olength, &output2, &olength) == 0)
    printf("%s: '%s' (%"PRINTF_SIZE_T")\n", output, output2, olength);
  else fprintf(stderr, "Unable to base64 decode: (%d) %s\n", errno, strerror(errno));

  free(output2);
  free(output);
  return 0;
}
