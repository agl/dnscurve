#ifndef DNS_H
#define DNS_H

// -----------------------------------------------------------------------------
// Read a DNS name from a packet, decoding jumps etc
//
// name: (output) the resulting name, in DNS length-prefixed, NUL terminated
//   format, but without jumps
// namemax: length of @name
// buf: DNS packet
// len: length of @buf
// pos: starting position to read the name from
// returns: 0 on error or the position following the name.
//
// Errno:
//   EPROTO: invalid packet
// -----------------------------------------------------------------------------
unsigned dns_packet_getname(uint8_t *name, unsigned namemax,
                            const uint8_t *buf, unsigned len, unsigned pos);

// -----------------------------------------------------------------------------
// Try to parse and decode a dnscurve query name
//
// box: (output) the 8-byte nonce and box (in binary form)
// boxlen: (in/out) number of bytes in @box on entry. Number of valid bytes on
//   successful exit
// publickey: (output) 32-byte array which receives the public key
// zone: (output) the offset into @name where the server's zone starts
// name: (input) a DNS name, without jumps and trusted to be valid
// returns: 1 on success, 0 otherwise
//
// Errno:
//   EPROTO: Invalid packet
//   E2BIG: one of the base32 values was too large
//   ENAMETOOLONG: too many box components found
// -----------------------------------------------------------------------------
int dns_curve_name_parse(uint8_t *box, unsigned *boxlen,
                         uint8_t *publickey, unsigned *zone,
                         const uint8_t *name);

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
int dns_curve_request_parse(uint8_t *plaintext, unsigned *plaintextlen,
                            uint8_t *public_key, uint8_t *nonce,
                            const uint8_t **qname, unsigned *qnamelen,
                            const uint8_t *buffer, unsigned n);


int dns_curve_request_build(uint8_t *output, unsigned *ooutlen,
                            const uint8_t *box, unsigned boxlen,
                            const uint8_t *public_key,
                            const uint8_t *zone);

#endif  // DNS_H
