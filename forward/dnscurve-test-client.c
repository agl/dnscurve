#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <nacl/crypto_box_curve25519salsa20hmacsha512.h>
#include <nacl/randombytes.h>

#include "ip_parse.h"
#include "dns.h"
#include "base32.h"

static int
usage(const char *argv0) {
  fprintf(stderr, "Usage: %s <target ip> <target port> <target public key>\n", argv0);
  return 1;
}

int global_urandom_fd;
uint8_t global_secret_key[32];

int
main(int argc, char **argv) {
  global_urandom_fd = open("/dev/urandom", O_RDONLY);
  if (global_urandom_fd < 0) {
    perror("Opening /dev/urandom");
    return 1;
  }

  if (argc != 4)
    return usage(argv[0]);

  uint32_t target_ip;

  if (!ip_parse(&target_ip, argv[1]))
    return usage(argv[0]);

  const unsigned portnum = strtoul(argv[2], NULL, 10);

  uint8_t server_pk[32];
  unsigned server_pk_len = sizeof(server_pk);
  if (!base32_decode(server_pk, &server_pk_len, (const uint8_t *) argv[3], strlen(argv[3]), 1)) {
    perror("base32_decode");
    return 1;
  }
  if (server_pk_len != 32) {
    fprintf(stderr, "Invalid server public key\n");
    return 1;
  }

  static const char query[] =
    "\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03org\x00\x00\x02\x00\x01";

  uint8_t pk[32];
  crypto_box_curve25519salsa20hmacsha512_keypair(pk, global_secret_key);

  uint8_t nonce_and_box[4096];
  randombytes(nonce_and_box, 8);
  crypto_box_curve25519salsa20hmacsha512(nonce_and_box + 8, query, sizeof(query) - 1,
                                         nonce_and_box, server_pk, global_secret_key);
  write(1, pk, 32);
  write(1, nonce_and_box, 8 + sizeof(query) + crypto_box_curve25519salsa20hmacsha512_AUTHBYTES);

  uint8_t request[4096];
  unsigned requestlen = sizeof(request) - 2;

  if (!dns_curve_request_build
    (request + 2, &requestlen,
     nonce_and_box, 8 + sizeof(query) - 1 +
                    crypto_box_curve25519salsa20hmacsha512_AUTHBYTES,
     pk, "\x06google\x03org\x00")) {
    perror("dns_curve_request_build");
    return 1;
  }

  requestlen += 2;

  const int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (fd < 0) {
    perror("socket");
    return 1;
  }

  struct sockaddr_in sin;
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = target_ip;
  sin.sin_port = htons(portnum);

  ssize_t n;
  do {
    n = sendto(fd, request, requestlen, 0, (struct sockaddr *) &sin, sizeof(sin));
  } while (n == -1 && errno == EINTR);

  if (n < 0) {
    perror("sendto");
    return 1;
  }

  return 0;
}
