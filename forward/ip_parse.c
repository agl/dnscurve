#define _BSD_SOURCE

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int
ip_parse(uint32_t *out, const char *in) {
  struct in_addr addr;

  if (!inet_aton(in, &addr)) {
    return 0;
  } else {
    *out = addr.s_addr;
    return 1;
  }
}
