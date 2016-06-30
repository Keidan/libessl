#include <essl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/select.h>
#include <signal.h>


#define SOCKET_MAX_CONNECTIONS 10
#define PORT 443
#define BUFFER_LENGTH 1024

#if !defined(OPENSSL_NO_SSL2) && !defined(OPENSSL_NO_BIO)
static char leave = 0;
static int fd;

void sig_callback(int sig);
#endif /* OPENSSL_NO_SSL2 && OPENSSL_NO_BIO */

int main(int argc, char** argv) {
#if !defined(OPENSSL_NO_SSL2) && !defined(OPENSSL_NO_BIO)
  struct sigaction sa;
  int i, max, reuse, activity, client, addrlen, sd, status;
  int clients[SOCKET_MAX_CONNECTIONS];
  fd_set readfds;
  struct sockaddr_in addr;
  struct sockaddr_in address;
  char found;
  essl_socket_t essl;
  char readdata[BUFFER_LENGTH];
  struct essl_file_s cert = { ESSL_FILE_TYPE_PEM, "./cert.pem"};
  struct essl_file_s private_key = { ESSL_FILE_TYPE_PEM, "./key.pem"};
  const char* page = "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"></head><body>Hello from SSL accept</body></html>";
  
  (void)argc;
  (void)argv;
  
  /* sigint + sigterm registration */
  memset(&sa, 0, sizeof(struct sigaction));
  sa.sa_handler = sig_callback;
  (void)sigaction(SIGINT, &sa, NULL);
  (void)sigaction(SIGTERM, &sa, NULL);
  
  if(essl_initialize_ssl() != 0) {
    fprintf(stderr, "Error: %s\n", essl_strerror_ssl());
    exit(1);
  }
  
  fd = socket(AF_INET, SOCK_STREAM, 0);
  if(fd < 0) {
    fprintf(stderr, "socket failed: (%d) %s.\n", errno, strerror(errno));
    exit(1);
  }
  reuse = 1;
  if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse)) != 0) {
    fprintf(stderr, "setsockopt: (%d) %s.\n", errno, strerror(errno));
    exit(1);
  }

  bzero((char *)&addr, sizeof(addr));  
  addr.sin_family = AF_INET;
  addr.sin_port = htons(PORT);
  addr.sin_addr.s_addr = INADDR_ANY;

  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
    fprintf(stderr, "bind: (%d) %s.\n", errno, strerror(errno));
    exit(1);
  }

  if(listen(fd, SOCKET_MAX_CONNECTIONS) != 0) {
    fprintf(stderr, "listen: (%d) %s.\n", errno, strerror(errno));
    exit(1);
  }
  /* initialize the clients */
  memset(clients, 0, SOCKET_MAX_CONNECTIONS * sizeof(int));

  printf("Listen on port %d for %d connexions\n", PORT, SOCKET_MAX_CONNECTIONS);

  while(!leave) {
    if(fd <= 0) break;
    /* clear the socket set */
    FD_ZERO(&readfds);
    /* add server socket to set */
    FD_SET(fd, &readfds);
    max = fd;
    /* add child sockets to set */
    for (i = 0; i < SOCKET_MAX_CONNECTIONS; i++) {
      /* socket descriptor */
      sd = clients[i];
      /* if valid socket descriptor then add to read list */
      if(sd > 0) FD_SET(sd ,&readfds);         
      /* highest file descriptor number, need it for the select function */
      if(sd > max) max = sd;
    }

    /* wait for an activity on one of the sockets, timeout is NULL, so wait indefinitely */
    activity = select(max + 1, &readfds, NULL, NULL, NULL);
    if ((activity < 0) && (errno!=EINTR)) {
      fprintf(stderr, "Select error: (%d) %s\n", errno, strerror(errno));
      break;
    }
          
    /* If something happened on the server socket , then its an incoming connection */
    if (FD_ISSET(fd, &readfds)) {
      bzero(&address, sizeof(struct sockaddr_in));
      addrlen = 0;
      if ((client = accept(fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
        fprintf(stderr, "Accept error: (%d) %s\n", errno, strerror(errno));
        break;
      }
      /* add log */
      printf("New connection , socket fd is %d , ip is: %s , port: %d\n" , client , inet_ntoa(address.sin_addr) , ntohs(address.sin_port));

      /* add new socket to array of sockets */
      found = 0;
      for (i = 0; i < SOCKET_MAX_CONNECTIONS; i++) {
        /* if position is empty */
        if(clients[i] == 0 ) {
          printf("Free slot found for sd %d at %d\n" , client , i);
          clients[i] = client;
          found = 1;
          break;
        }
      }
      if(!found) {
        fprintf(stderr, "No free socket was found\n");
        close(client);
      }
      continue;
    }

    /* else its some IO operation on some other socket :) */
    for (i = 0; i < SOCKET_MAX_CONNECTIONS; i++) {
      sd = clients[i];
      if (FD_ISSET(sd, &readfds)) {
        printf("for me\n");
        clients[i] = 0;
        essl = essl_accept_ssl(sd, cert, private_key);
        if(essl == NULL) {
          fprintf(stderr, "Error: %s\n", essl_strerror_ssl());
          close(sd);
          break;
        }
        bzero(readdata, BUFFER_LENGTH);
        status = essl_read_ssl(essl, readdata, BUFFER_LENGTH);
        if ( status == 0 ) printf("Status equals 0\n");
        else if ( status <  0 ) printf("Status equals %d\n", status);
        else {
          fprintf(stdout, "Message: '%s'", readdata);
          essl_write_ssl(essl, page, strlen(page));
        }
        essl_close_ssl(essl);
        close(sd);
        return 0;
      }
    }
  }
#else
  (void)argc;
  (void)argv;
  printf("SSL and BIO are not supported\n");
#endif /* OPENSSL_NO_SSL2 && OPENSSL_NO_BIO */
  return 0;
}

#if !defined(OPENSSL_NO_SSL2) && !defined(OPENSSL_NO_BIO)

void sig_callback(int sig) {
  (void)sig;
  leave = 1;
  if(fd > 0) {
    close(fd);
    fd = 0;
  }
  essl_release_ssl();
}

#endif /* OPENSSL_NO_SSL2 && OPENSSL_NO_BIO */
