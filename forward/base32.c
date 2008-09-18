#include <stdint.h>
#include <errno.h>

static const uint8_t kValues[] =
  {99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,
    99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,0,1,
    2,3,4,5,6,7,8,9,99,99,99,99,99,99,99,10,11,12,13,14,15,16,17,18,19,20,21,
    22,23,24,25,26,27,28,29,30,31,99,99,99,99,99,99,99,99,99,99,10,11,12,13,14,
    15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,99,99,99,99,99,99,99,99,99};

int
base32_decode(uint8_t *output, unsigned *ooutlen,
              const uint8_t *in, unsigned inlen, int mode) {
  unsigned i = 0, j = 0;
  unsigned v = 0, bits = 0;
  const unsigned outlen = *ooutlen;

  while (j < inlen) {
    if (in[j] & 0x80)
      goto PROTO;
    const uint8_t b = kValues[in[j++]];
    if (b > 31)
      goto PROTO;

    v |= ((unsigned) b) << bits;
    bits += 5;

    if (bits >= 8) {
      if (i >= outlen)
        goto TOOBIG;
      output[i++] = v;
      bits -= 8;
      v >>= 8;
    }
  }

  if (mode) {
    if (bits && i >= outlen)
      goto TOOBIG;
    output[i++] = v & ((1 << bits) - 1);
  }

  *ooutlen = i;
  return 1;

 TOOBIG:
  errno = E2BIG;
  return 0;

 PROTO:
  errno = EPROTO;
  return 0;
}

int
base32_encode(uint8_t *output, unsigned *ooutlen, const uint8_t *in, unsigned inlen) {
  unsigned i = 0, j = 0;
  unsigned v = 0, bits = 0;
  const unsigned outlen = *ooutlen;
  static const char kChars[] = "0123456789abcdefghijklmnopqrstuv";

  while (j < inlen) {
    v |= ((unsigned) in[j++]) << bits;
    bits += 8;

    while (bits >= 5) {
      if (i >= outlen)
        goto TOOBIG;
      output[i++] = kChars[v & 31];
      bits -= 5;
      v >>= 5;
    }
  }

  if (bits && i >= outlen)
    goto TOOBIG;
  output[i++] = kChars[v];

  *ooutlen = i;

  return 1;

 TOOBIG:
  errno = E2BIG;
  return 0;
}
