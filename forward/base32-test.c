#include <stdio.h>
#include <stdint.h>

#include "base32.h"

int
main(int argc, char **argv) {
  uint8_t a[128];
  unsigned alen = sizeof(a);

  if (!base32_encode(a, &alen, argv[1], strlen(argv[1]))) {
    perror("encode");
    return 1;
  }

  write(1, a, alen);
  write(1, "\n", 1);

  uint8_t b[128];
  unsigned blen = sizeof(b);

  if (!base32_decode(b, &blen, a, alen)) {
    perror("decode");
    return 1;
  }

  write(1, b, blen);
  write(1, "\n", 1);

  return 0;
}
