#include <essl.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>

#define EXIT_NOT_SUPPORTED 2

#define FOO_SHA1_TEXT "0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33"
#define FOO_SHA1_FILE "ed5bec7c4581eac9172d96184b0854f4124a829a"

static void get_path(const char* argv0, char* opath);

int main(int argc, char** argv)
{
  (void)argc;/* remove warning */
  (void)argv;/* remove warning */
#ifdef ESSL_SUPPORT_SHA1
  const char* str = "foo";
  essl_sha1_string_t output;
  char file_path[PATH_MAX];

  (void)argc;/* remove warning */
  
  if(essl_sha1_do_hash(str, strlen(str), output) == 0)
    printf("%s: '%s'\n", str, output);
  else fprintf(stderr, "Unable to sha1: (%d) %s\n", errno, strerror(errno));

  if(strcmp(output, FOO_SHA1_TEXT) != 0)
    return EXIT_FAILURE;
  
  get_path(argv[0], file_path);
  strcat(file_path, "/generate_cert.sh");
  if(essl_sha1_do_hash_file(file_path, output) == 0)
    printf("%s: '%s'\n", file_path, output);
  else fprintf(stderr, "Unable to sha1: (%d) %s -> %s\n", errno, strerror(errno), file_path);

  return strcmp(output, FOO_SHA1_FILE) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
#else
  printf("SHA1 not supported\n");
  return EXIT_NOT_SUPPORTED;
#endif /* ESSL_SUPPORT_SHA1 */
}

static void get_path(const char* argv0, char* opath)
{
  char ipath[PATH_MAX];
  char *p;
  int n;
  if(!(p = strrchr(argv0, '/')))
    p = getcwd(ipath, sizeof(ipath));
  else
  {
    *p = '\0';
    n = chdir(argv0);
    p = getcwd(ipath, sizeof(ipath));
    (void)n;
  }
  strcpy(opath, ipath);
}
