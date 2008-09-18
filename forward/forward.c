#define _POSIX_C_SOURCE 200809

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <nacl/crypto_box_curve25519salsa20hmacsha512.h>
#include <nacl/randombytes.h>

#include "dns.h"
#include "ip_parse.h"
#include "dns_random.h"

// The server's private key
uint8_t global_secret_key[32];
// An open descriptor to /dev/urandom
int global_urandom_fd = -1;
// The IP address (big-endian) of the backend server
static uint32_t global_target_address;

static const unsigned TIMEOUT = 5000;  // 5 seconds

// -----------------------------------------------------------------------------
// Our timeouts are special since they are always for the same amount of time.
// Thus we simply have a double-linked list for timeouts. When transmitting a
// packet we put the txidentry at the head of the timeout queue and we expire
// entries from the tail. When a reply comes back, the double-linked nature of
// the list means that we can remove the element quickly.
// -----------------------------------------------------------------------------
struct txidentry {
  struct txidentry *to_prev, *to_next;  // timeout double-linked list
  uint64_t tx_time;                     // transmit time (milliseconds)
  int fd;                               // socket
  uint32_t source_ip;
  uint16_t source_port;
  uint16_t source_txid;

  char is_dnscurve;

  // The following are only valid if @is_dnscurve is non-zero
  uint8_t public_key[32];
  uint8_t nonce[8];
  uint16_t qnamelen;                  // length of the client's query name
  uint8_t qname[0];                    // query name follows directly
};

// The head and tail of the timeout queue.
static struct txidentry *global_txid_to_head = NULL;
static struct txidentry *global_txid_to_tail = NULL;

// -----------------------------------------------------------------------------
// Append data to a buffer, if it will fit
//
// output: a buffer
// len: the length of @output
// pos: (in/out) the current position in @buffer - updated on exit
// input: the data to be appended
// inlen: the length of @input
// returns: 1 on success, 0 otherwise
// -----------------------------------------------------------------------------
static int
buffer_append(uint8_t *output, unsigned len, unsigned *pos,
              const void *input, unsigned inlen) {
  if (*pos + inlen > len)
    return 0;

  memcpy(output + *pos, input, inlen);
  *pos += inlen;

  return 1;
}

// -----------------------------------------------------------------------------
// Return the current mission time in milliseconds
// -----------------------------------------------------------------------------
static uint64_t
time_now() {
  struct timespec ts;

  if (clock_gettime(CLOCK_MONOTONIC, &ts)) {
    perror("clock_gettime");
    abort();  // there are no temporary errors with clock_gettime
  }

  uint64_t msecs = ts.tv_sec;
  msecs *= 1000;
  msecs += ts.tv_nsec / 1000000;

  return msecs;
}

// -----------------------------------------------------------------------------
// Get a socket with a random port number to transmit on or -1 on error
// -----------------------------------------------------------------------------
static int
tx_socket_get() {
  const int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sock < 0)
    return -1;

  struct sockaddr_in sin;
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;

  for (unsigned i = 0; i < 10; ++i) {
    uint16_t port = 1025 + dns_random(64510);
    sin.sin_port = htons(port);

    if (bind(sock, (struct sockaddr *) &sin, sizeof(sin)) == 0)
      return sock;
  }

  // Give up and let the kernel pick the port number for us.
  return sock;
}

// -----------------------------------------------------------------------------
// Expire any txids
// -----------------------------------------------------------------------------
static void
txids_expire(uint64_t current_time) {
  while (global_txid_to_tail) {
    struct txidentry *entry = global_txid_to_tail;
    if (entry->tx_time + TIMEOUT < current_time) {
      if (entry->to_prev) {
        entry->to_prev->to_next = NULL;
        global_txid_to_tail = entry->to_prev;
      } else {
        global_txid_to_head = NULL;
        global_txid_to_tail = NULL;
      }
      close(entry->fd);
      free(entry);
    } else {
      break;
    }
  }
}

// -----------------------------------------------------------------------------
// Return the number of milliseconds until the next txid expires, or -1 if
// nothing is inflight.
// -----------------------------------------------------------------------------
static int
txids_expire_sleep(uint64_t current_time) {
  if (!global_txid_to_tail)
    return -1;

  if (global_txid_to_tail->tx_time + TIMEOUT < current_time)
    return 0;
  return (10 + global_txid_to_tail->tx_time + TIMEOUT) - current_time;
}

// -----------------------------------------------------------------------------
// Transmit a packet to the server on a new socket. Return the txidentry of the
// new request with @fd valid.
//
// extra: extra bytes to allocate at the end of the returned txidentry
// -----------------------------------------------------------------------------
static struct txidentry *
dns_transmit(const uint8_t *packet, unsigned len, unsigned extra) {
  int sock = tx_socket_get();
  if (sock < 0)
    return NULL;

  struct sockaddr_in sin;
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = global_target_address;
  sin.sin_port = htons(53);

  ssize_t n;

  do {
    n = sendto(sock, packet, len, MSG_DONTWAIT, (struct sockaddr *) &sin, sizeof(sin));
  } while (n == -1 && errno == EINTR);

  if (n != len) {
    close(sock);
    return NULL;
  }

  struct txidentry *entry = malloc(sizeof(struct txidentry) + extra);
  if (!entry) {
    close(sock);
    return NULL;
  }
  entry->fd = sock;

  return entry;
}

// -----------------------------------------------------------------------------
// Forward a packet to the backend server
//
// packet: DNS packet
// length: number of bytes in @packet
// efd: epoll file descriptor into which the new socket is added
// sin: source location
// is_dnscurve: true iff the source packet was DNS curve protected
// public_key: (if @is_dnscurve) the client's public key (32 bytes)
// nonce: (if @is_dnscurve) the client's nonce (8 bytes)
// qname: (if @is_dnscurve) the original query string
// qnamelen: (if @is_dnscurve) number of bytes in @qname
// -----------------------------------------------------------------------------
static void
dns_forward(const uint8_t *packet, unsigned length, int efd,
            const struct sockaddr_in *sin, char is_dnscurve,
            const uint8_t *public_key, const uint8_t *nonce,
            const uint8_t *qname, unsigned qnamelen) {
  if (length < 16)
    return;  // clearly bogus, drop it.

  struct txidentry *entry = dns_transmit(packet, length, is_dnscurve ? qnamelen : 0);
  if (!entry)
    return;

  entry->is_dnscurve = is_dnscurve;
  if (is_dnscurve) {
    memcpy(entry->public_key, public_key, 32);
    memcpy(entry->nonce, nonce, 8);
    entry->qnamelen = qnamelen;
    memcpy(entry->qname, qname, qnamelen);
  }

  struct epoll_event event;
  event.data.ptr = entry;
  event.events = EPOLLIN;

  if (epoll_ctl(efd, EPOLL_CTL_ADD, entry->fd, &event)) {
    close(entry->fd);
    free(entry);
  }

  entry->source_port = sin->sin_port;
  entry->source_ip = sin->sin_addr.s_addr;
  entry->source_txid = *((uint16_t *) packet);
  entry->tx_time = time_now();

  entry->to_prev = NULL;
  entry->to_next = global_txid_to_head;
  if (!entry->to_next) {
    global_txid_to_tail = entry;
  } else {
    entry->to_next->to_prev = entry;
  }
  global_txid_to_head = entry;
}

// -----------------------------------------------------------------------------
// Pass a reply back to the requestor
//
// packet: the reply from the backend server. 8 free bytes are available preceeding
//   this buffer
// length: number of bytes in @packet
// entry: the txidentry for this request
// -----------------------------------------------------------------------------
static void
dns_reply(uint8_t *packet, unsigned length, struct txidentry *entry) {
  if (entry->to_prev) {
    entry->to_prev->to_next = entry->to_next;
  } else {
    global_txid_to_head = entry->to_next;
  }

  if (entry->to_next) {
    entry->to_next->to_prev = entry->to_prev;
  } else {
    global_txid_to_tail = entry->to_prev;
  }

  struct sockaddr_in sin;
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = entry->source_ip;
  sin.sin_port = entry->source_port;

  if (!entry->is_dnscurve) {
    ssize_t n;

    do {
      n = sendto(3, packet, length, MSG_DONTWAIT,
                 (struct sockaddr *) &sin, sizeof(sin));
    } while (n == -1 && errno == EINTR);

    return;
  }

  // client is DNS curve. Need to construct a wrapping

  uint8_t wrapper[4096];
  uint8_t nonce_and_box[4096];
  randombytes(nonce_and_box, 8);

  if (8 + length + crypto_box_curve25519salsa20hmacsha512_AUTHBYTES +
      crypto_box_curve25519salsa20hmacsha512_EXTRABYTES >
      sizeof(nonce_and_box) - 8)
    return;

  memcpy(packet - 8, entry->nonce, 8);

  crypto_box_curve25519salsa20hmacsha512(nonce_and_box + 8, packet - 8, length + 8,
                                         nonce_and_box, entry->public_key,
                                         global_secret_key);
  const unsigned payload_length =
    length + 8 + 8 + crypto_box_curve25519salsa20hmacsha512_AUTHBYTES;

  unsigned pos = 0;
  if (!buffer_append(wrapper, sizeof(wrapper), &pos, &entry->source_txid, 2))
    return;
  if (!buffer_append(wrapper, sizeof(wrapper), &pos,
                     "\x84"  // response, opcode 0, authoritative,
                             // not truncated, recursion not desired
                     "\x00"  // recursion not available, no Z bits, RCODE 0
                     "\x00\x01"   // one question
                     "\x00\x01"  // one answer
                     "\x00\x00"  // no authority
                     "\x00\x00", // no additional
                     10))
    return;
  if (!buffer_append(wrapper, sizeof(wrapper), &pos,
                     entry->qname, entry->qnamelen))
    return;
  if (!buffer_append(wrapper, sizeof(wrapper), &pos,
                     "\x00\x10"  // query type TXT
                     "\x00\x01"  // Internet class
                     "\xc0\x0c"  // pointer back to the first qname
                     "\x00\x10"  // TXT reply
                     "\x00\x01"  // Internet class
                     "\x00\x00\x00\x00",  // TTL 0
                     14))
    return;

  // The DNS RDATA is a series of charactor strings, which are 8-bit length
  // prefixed strings. Thus we need to split the nonce_and_box into parts, at
  // most 255 bytes long.
  const unsigned rdatalen = payload_length + (payload_length + 254) / 255;
  const uint16_t rdatalen_be = htons(rdatalen);

  if (!buffer_append(wrapper, sizeof(wrapper), &pos, &rdatalen_be, 2))
    return;

  unsigned todo = payload_length, i = 0;
  while (todo) {
    unsigned stringlen = todo;
    if (stringlen > 255) stringlen = 255;
    const uint8_t strlenbyte = stringlen;

    if (!buffer_append(wrapper, sizeof(wrapper), &pos, &strlenbyte, 1))
      return;

    if (!buffer_append(wrapper, sizeof(wrapper), &pos, nonce_and_box + i, stringlen))
      return;

    todo -= stringlen;
    i += stringlen;
  }

  ssize_t n;

  do {
    n = sendto(3, wrapper, pos, MSG_DONTWAIT,
               (struct sockaddr *) &sin, sizeof(sin));
  } while (n == -1 && errno == EINTR);
}

static int
curve_worker() {
  uint8_t buffer[4096];
  uint8_t plaintext[4096];
  unsigned plaintextlen;

  const int efd = epoll_create(32);
  if (efd < 0) {
    perror("epoll_create");
    return 1;
  }

  struct epoll_event curve_event;
  curve_event.data.ptr = NULL;
  curve_event.events = EPOLLIN;
  if (epoll_ctl(efd, EPOLL_CTL_ADD, 3, &curve_event)) {
    perror("epoll_ctl");
    return 1;
  }

  for (;;) {
    struct epoll_event events[8];

    uint64_t current_time = time_now();
    txids_expire(current_time);

    int r;
    do {
      r = epoll_wait(efd, events, 8, txids_expire_sleep(current_time));
    } while (r == -1 && errno == EINTR);

    if (r < 0) {
      perror("epoll_wait");
      return 1;
    }

    struct sockaddr_in sin;
    socklen_t sinlen;
    ssize_t n;
    const uint8_t *qname;
    unsigned qnamelen;
    uint8_t public_key[32], nonce[8];

    for (unsigned i = 0; i < r; ++i) {
      if (events[i].data.ptr == NULL) {
        // This is the world facing, DNS curve, UDP socket

        sinlen = sizeof(sin);
        do {
          n = recvfrom(3, buffer, sizeof(buffer), MSG_DONTWAIT,
                       (struct sockaddr *) &sin, &sinlen);
        } while (n == -1 && errno == EINTR);

        if (n < 0) {
          perror("reading from curve socket");
          continue;
        }

        plaintextlen = sizeof(plaintext);
        int cr;
        cr = dns_curve_request_parse(plaintext, &plaintextlen, public_key,
                                     nonce, &qname, &qnamelen, buffer, n);
        if (cr == 0) {
          // not a DNS curve packet. Forward directly
          dns_forward(buffer, n, efd, &sin, 0, NULL, NULL, NULL, 0);
        } else if (cr == -1) {
          // invalid DNS curve packet. Drop
        } else {
          // valid DNS curve packet, inner packet in plaintext
          dns_forward(plaintext, plaintextlen, efd, &sin, 1, public_key, nonce,
                      qname, qnamelen);
        }
      } else {
        // this is a socket talking to our server
        struct txidentry *entry = events[i].data.ptr;

        sinlen = sizeof(sin);
        do {
          n = recvfrom(entry->fd, buffer + 8, sizeof(buffer) - 8, MSG_DONTWAIT,
                       (struct sockaddr *) &sin, &sinlen);
        } while (n == -1 && errno == EINTR);

        if (n < 0) {
          perror("reading from curve socket");
          continue;
        }

        if (sin.sin_addr.s_addr != global_target_address ||
            sin.sin_port != htons(53) ||
            n < 2 ||
            *((uint16_t *) (buffer + 8)) != entry->source_txid)
          continue;  // bogus packet

        dns_reply(buffer + 8, n, entry);

        close(entry->fd);
        free(entry);
      }
    }
  }

  return 1;
}

static int
hex_char(uint8_t *out, char in) {
  if (in >= '0' && in <= '9') {
    *out = in - '0';
    return 1;
  } else if (in >= 'a' && in <= 'f') {
    *out = 10 + (in - 'a');
    return 1;
  } else if (in >= 'A' && in <= 'F') {
    *out = 10 + (in - 'A');
    return 1;
  } else {
    return 0;
  }
}

static int
hex_decode(uint8_t *dest, const char *src) {
  while (*src) {
    uint8_t v1, v2;
    if (!hex_char(&v1, *src++))
      return 0;
    if (!hex_char(&v2, *src++))
      return 0;

    *dest++ = (v1 << 4) | v2;
  }

  return 1;
}

static int
usage(const char *argv0) {
  fprintf(stderr, "Usage: %s <DNS server IP>\n", argv0);
  return 1;
}

int
main(int argc, char **argv) {
  if (argc != 2) return usage(argv[0]);

  if (!ip_parse(&global_target_address, argv[1]))
    return usage(argv[0]);

  global_urandom_fd = open("/dev/urandom", O_RDONLY);
  if (global_urandom_fd < 0) {
    perror("Opening /dev/urandom");
    return 1;
  }

  dns_random_init();

  if (!getenv("DNSCURVE_PRIVATE_KEY")) {
    fprintf(stderr, "$DNSCURVE_PRIVATE_KEY must be set\n");
    return 1;
  }

  if (strlen(getenv("DNSCURVE_PRIVATE_KEY")) != 64) {
    fprintf(stderr, "$DNSCURVE_PRIVATE_KEY must 64 bytes long\n");
    return 1;
  }

  if (!hex_decode(global_secret_key, getenv("DNSCURVE_PRIVATE_KEY"))) {
    fprintf(stderr, "$DNSCURVE_PRIVATE_KEY invalid\n");
    return 1;
  }

  global_secret_key[0] &= 248;
  global_secret_key[31] &= 127;
  global_secret_key[31] |= 64;

  return curve_worker();
}
