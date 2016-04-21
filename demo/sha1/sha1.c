#include <essl.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {

  const char* str = "Hello world";
  essl_sha1_string_t output;

  (void)argc;/* remove warning */
  
  if(essl_sha1_do_hash(str, strlen(str), output) == 0)
    printf("%s: '%s'\n", str, output);
  else fprintf(stderr, "Unable to sha1: (%d) %s\n", errno, strerror(errno));
  
  if(essl_sha1_do_hash_file(argv[0], output) == 0)
    printf("%s: '%s'\n", argv[0], output);
  else fprintf(stderr, "Unable to sha1: (%d) %s\n", errno, strerror(errno));

  return 0;
}
