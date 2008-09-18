#ifndef BASE_32_H
#define BASE_32_H

#include <stdint.h>

int base32_decode(uint8_t *output, unsigned *ooutlen,
                  const uint8_t *in, unsigned inlen, int mode);
int base32_encode(uint8_t *output, unsigned *ooutlen,
                  const uint8_t *in, unsigned inlen);

#endif  // BASE_32_H
