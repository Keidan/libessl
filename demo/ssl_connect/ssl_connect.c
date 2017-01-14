#include <essl.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>

int main(int argc, char** argv) {
#if defined(OPENSSL_NO_SSL2) && defined(OPENSSL_NO_BIO)
  struct hostent *remoteh;
  struct sockaddr_in address;
  int fd, result, status;
  essl_socket_t essl;
  char readdata[1024];
  
  sleep(5); /* wait forthecertificate generation */
  
  if(essl_initialize_ssl() != 0) {
    fprintf(stderr, "Error: %s\n", essl_strerror_ssl());
    essl_release_ssl();
    exit(1);
  }
  
      
  /* Get a socket to work with.  This socket will be in the Internet domain, and */
  /* will be a stream socket. */
  if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	  perror( "connect: cannot create socket" );
    essl_release_ssl();
	  exit(1);
  } 
  
  /* Look up the remote host to get its network number. */
	if ((remoteh = gethostbyname(argc > 1 ? argv[1] : "127.0.0.1")) == NULL) {
    perror("connect");
    essl_release_ssl();
    close(fd);
	  exit(1);
	}

  /* Initialize the address varaible, which specifies where connect() should attempt to connect. */
  bcopy(remoteh->h_addr, &address.sin_addr, remoteh->h_length);
  address.sin_family = AF_INET;
  address.sin_port = htons(443);

  if (!(connect(fd, (struct sockaddr *)(&address), sizeof(address)) >= 0)) {
    perror("connect");
    essl_release_ssl();
    close(fd);
	  exit(1);
	}
  
  essl = essl_connect_ssl(fd);
  if(essl == NULL) {
    fprintf(stderr, "Error: %s\n", essl_strerror_ssl());
    essl_release_ssl();
    close(fd);
    exit(1);
  }
  
  /* Send the request */
  strcpy(readdata, "GET /\r\n");
  result = essl_write_ssl(essl, readdata, strlen(readdata));
  /* wait a second for processing. */
  sleep(1);
  bzero(readdata, 1024);
  while (1) {
    status = essl_read_ssl(essl, readdata, 1024);
	  if ( status == 0 ) break;
	  if ( status <  0 ) { sleep(1); continue; }
	  fprintf(stdout, "%s\n", readdata);
  }
  essl_close_ssl(essl);
  close(fd);
  essl_release_ssl();
#else
  printf("SSL and BIO are not supported\n");
#endif /* OPENSSL_NO_SSL2 && OPENSSL_NO_BIO */
  return 0;
}
