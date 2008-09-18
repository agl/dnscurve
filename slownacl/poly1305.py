from verify import crypto_verify_16

P = 2 ** 130 - 5

def limb(s):
  return unpack(s) + (1 << 8 * len(s))

def unpack(s):
  return sum(ord(s[i]) << 8 * i for i in range(len(s)))

def pack(n):
  return ''.join([chr(n >> 8 * i & 255) for i in range(16)])

def crypto_onetimeauth_poly1305(m, kr):
  if len(kr) != 32: raise ValueError('Invalid Poly1305 key')
  k = unpack(kr[:16])
  r = unpack(kr[16:])

  h = 0
  for i in range(0, len(m), 16):
    c = limb(m[i:i+16])
    h = (h + c) * r % P
  h += k

  return pack(h)

def crypto_onetimeauth_poly1305_verify(a, m, k):
  return crypto_verify_16(a, crypto_onetimeauth_poly1305(m, k))
