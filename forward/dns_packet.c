#include <stdint.h>
#include <errno.h>
#include <string.h>

#include <nacl/crypto_box_curve25519salsa20hmacsha512.h>

#include "dns.h"
#include "base32.h"

extern uint8_t global_secret_key[32];

unsigned
dns_packet_getname(uint8_t *name, unsigned namemax,
                   const uint8_t *buf, unsigned len, unsigned pos) {
  unsigned int loop = 0;
  unsigned int state = 0;
  unsigned int firstcompress = 0;
  unsigned int where;
  uint8_t ch;
  unsigned int namelen = 0;

  for (;;) {
    if (pos >= len) goto PROTO;
    ch = buf[pos++];
    if (++loop >= 4096) goto PROTO;

    if (state) {
      if (namelen + 1 > namemax) goto PROTO;
      name[namelen++] = ch;
      --state;
    } else {
      while (ch >= 192) {
        where = ch; where -= 192; where <<= 8;
        if (pos >= len) goto PROTO;
        ch = buf[pos++];
        if (!firstcompress) firstcompress = pos;
        pos = where + ch;
        if (pos >= len) goto PROTO;
        ch = buf[pos++];
        if (++loop >= 4096) goto PROTO;
      }
      if (ch >= 64) goto PROTO;
      if (namelen + 1 > namemax) goto PROTO;
      name[namelen++] = ch;
      if (!ch) break;
      state = ch;
    }
  }

  if (firstcompress) return firstcompress;
  return pos;

 PROTO:
  errno = EPROTO;
  return 0;
}

int
dns_curve_name_parse(uint8_t *box, unsigned *boxlen,
                     uint8_t *publickey, unsigned *zone,
                     const uint8_t *name) {
  uint8_t encoded_box[4096];
  unsigned encoded_boxlen = 0;
  unsigned i = 0;

  errno = EPROTO;

  // Concatenate the base32 encoded components which make up the nonce and box
  for (;;) {
    const uint8_t component_len = name[i];
    if (component_len == 54) {
      break;
    } else if (component_len > 50) {
      return 0;
    } else if (component_len == 0) {
      return 0;
    }

    if (encoded_boxlen + component_len > sizeof(encoded_box))
      goto NAMETOOLONG;
    memcpy(encoded_box + encoded_boxlen, name + i + 1, component_len);
    encoded_boxlen += component_len;
    i += component_len + 1;
  }

  // Base32 decode the box
  if (!base32_decode(box, boxlen, encoded_box, encoded_boxlen, 0))
    return 0;

  // Next is the public key
  if (!(name[i] == 54 &&
        name[i+1] == 'x' &&
        name[i+2] == '1' &&
        name[i+3] == 'a'))
    return 0;

  unsigned publickeylen = 32;
  if (!base32_decode(publickey, &publickeylen, name + i + 4, 51, 1))
    return 0;
  if (publickeylen != 32)
    return 0;

  i += 54 + 1;
  *zone = i;

  return 1;

 NAMETOOLONG:
  errno = ENAMETOOLONG;
  return 0;
}

// -----------------------------------------------------------------------------
// Try to parse a packet as a DNS curve request
//
// plaintext: (output) a 4096 byte buffer which receives the enclosed packet
// plaintextlen: (output) on success, the length of the data in @plaintext
// public_key: (output) the client's public key (32-bytes)
// nonce: (output) the client's nonce (8-bytes)
// qname: (output) set to point within @buffer to the start of the query name
// qnamelen: (output) set to contain the number of bytes of query name
// buffer: the packet contents
// n: number of bytes in @buffer
// returns: 1 on success, 0 if this doesn't appear to be a DNS curve packet and
//   -1 if the DNS curve packet is invalid
// -----------------------------------------------------------------------------
int
dns_curve_request_parse(uint8_t *plaintext, unsigned *plaintextlen,
                        uint8_t *public_key, uint8_t *nonce,
                        const uint8_t **qname, unsigned *qnamelen,
                        const uint8_t *buffer, unsigned n) {
  // The DNSCurve format is quite strict. This is an absolute minimum number
  // of bytes
  if (n < 17)
    return 0;

  // First two bytes are the client selected transaction id
  uint16_t transid;
  memcpy(&transid, buffer, 2);

  if (memcmp(buffer + 2, "\x00" // query, opcode 0, not authoritative, not
                                // truncated, recursion not desired
                         "\x00" // recursion not available, no Z bits, RCODE 0
                         "\x00\x01"  // exactly one question
                         "\x00\x00"  // no answer records
                         "\x00\x00"  // no authority records
                         "\x00\x00", // no additional records
                         10))
    return 0;

  uint8_t queryname[4096];
  unsigned pos = 12;

  *qname = buffer + 12;
  pos = dns_packet_getname(queryname, sizeof(queryname), buffer, n, pos);
  if (!pos)
    return 0;
  *qnamelen = pos - 12;

  if (n - pos != 4)
    return 0;

  if (memcmp(&buffer[pos], "\x00\x10"      // query type TXT
                           "\x00\x01", 4)) // internet class
    return 0;

  uint8_t nonce_and_box[4096];
  unsigned server_zone, nonce_and_box_len = sizeof(nonce_and_box);
  if (!dns_curve_name_parse(nonce_and_box, &nonce_and_box_len,
                            public_key, &server_zone, queryname))
    return 0;

  if (nonce_and_box_len < 8 + crypto_box_curve25519salsa20hmacsha512_ref_AUTHBYTES)
    return 0;

  if (*plaintextlen < (nonce_and_box_len - 8) + crypto_box_curve25519salsa20hmacsha512_EXTRABYTES)
    return 0;

  if (-1 == crypto_box_curve25519salsa20hmacsha512_open
      (plaintext, nonce_and_box + 8, nonce_and_box_len - 8,
       nonce_and_box, public_key, global_secret_key))
    return -1;

  memcpy(nonce, nonce_and_box, 8);
  *plaintextlen = nonce_and_box_len - 8 - crypto_box_curve25519salsa20hmacsha512_AUTHBYTES;

  return 1;
}

int
dns_curve_request_build(uint8_t *output, unsigned *ooutlen,
                        const uint8_t *box, unsigned boxlen,
                        const uint8_t *public_key,
                        const uint8_t *zone) {
  uint8_t encoded[4096];
  unsigned encodedlen = sizeof(encoded);
  unsigned i = 0, j = 0;
  const unsigned outlen = *ooutlen;

  if (i + 10 > outlen)
    goto TOOBIG;

  memcpy(output + i, "\x00" // query, opcode 0, not authoritative, not
                            // truncated, recursion not desired
                     "\x00" // recursion not available, no Z bits, RCODE 0
                     "\x00\x01"  // exactly one question
                     "\x00\x00"  // no answer records
                     "\x00\x00"  // no authority records
                     "\x00\x00", // no additional records
                     10);
  i += 10;

  if (!base32_encode(encoded, &encodedlen, box, boxlen))
    return 0;

  while (encodedlen) {
    unsigned component_length = encodedlen;
    if (component_length > 50)
      component_length = 50;

    if (i >= outlen)
      goto TOOBIG;
    output[i++] = component_length;
    if (i + component_length >= outlen)
      goto TOOBIG;
    memcpy(output + i, encoded + j, component_length);
    encodedlen -= component_length;
    j += component_length;
    i += component_length;
  }

  encodedlen = sizeof(encoded);
  if (!base32_encode(encoded, &encodedlen, public_key, 32))
    return 0;
  if (i + 55 >= outlen)
    goto TOOBIG;

  memcpy(output + i, "\x36x1a", 4);
  i += 4;
  memcpy(output + i, encoded, 51);
  i += 51;

  j = 0;
  while (zone[j]) {
    const unsigned component_length = zone[j++];
    if (i >= outlen)
      goto TOOBIG;
    output[i++] = component_length;
    if (i + component_length >= outlen)
      goto TOOBIG;
    memcpy(output + i, zone + j, component_length);
    i += component_length;
    j += component_length;
  }
  if (i >= outlen)
    goto TOOBIG;
  output[i++] = 0;

  if (i + 4 > outlen)
    goto TOOBIG;

  memcpy(output + i, "\x00\x10"      // query type TXT
                     "\x00\x01", 4); // internet class
  i += 4;

  *ooutlen = i;

  return 1;

 TOOBIG:
  errno = E2BIG;
  return 0;
}
