// -----------------------------------------------------------------------------
// udpserver: start a child process with a UDP socket bound on fd 3
//
// % udpserver 0.0.0.0 53 my-dns-server
//
// Since binding to ports < 1024 is a priviledged operation, it's good to
// separate it from the process that will end up using the socket in question.
// Thus a pipeline like:
//
// % udpserver 0.0.0.0 53 setuidgid nonroot my-dns-server
//
// Can be used to ensure that my-dns-server doesn't need root to run.
//
// The child process must expect the UDP socket to be installed on fd 3.
// -----------------------------------------------------------------------------
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include "ip_parse.h"

static int
usage(const char *argv0) {
  fprintf(stderr, "Usage: %s <IP address> <UDP port number> <child process and args>\n",
          argv0);
  return 1;
}

int
main(int argc, char **argv) {
  if (argc < 4)
    return usage(argv[0]);

  uint32_t bind_ip;
  if (!ip_parse(&bind_ip, argv[1]))
    return usage(argv[0]);

  char *endptr;
  unsigned long port = strtoul(argv[2], &endptr, 10);
  if (*endptr)
    return usage(argv[0]);

  if (port == 0 || port > 65535) {
    fprintf(stderr, "Port number out of range (1..65535)\n");
    return 1;
  }

  const int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sock < 0) {
    perror("socket");
    return 1;
  }

  struct sockaddr_in sin;
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = bind_ip;
  sin.sin_port = htons(port);

  int n;
  do {
    n = bind(sock, (struct sockaddr *) &sin, sizeof(sin));
    if (n) {
      if (errno == EADDRINUSE || errno == ENOMEM) {
        sleep(1);
        continue;
      }
      perror("bind");
      return 1;
    }
  } while (n);

  if (sock != 3) {
    dup2(sock, 3);
    close(sock);
  }

  execvp(argv[3], &argv[3]);
  perror("execvp");

  return 1;
}
