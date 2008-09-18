import hashlib
from util import xor
from verify import crypto_verify_32

# Python has an hmac module, but at least as of 2.5.1, it assumed a
# block size of 64 bytes regardless of hash function, whereas SHA-512
# uses a block size of 128 bytes.

def crypto_hash_sha512(m):
  return hashlib.sha512(m).digest()

def crypto_auth_hmacsha512(m, k):
  if len(k) != 32: raise ValueError('Invalid key size for HMACSHA512')
  def pad(c): return xor(chr(c) * 128, k + '\0' * 96)
  m = crypto_hash_sha512(pad(0x36) + m)
  m = crypto_hash_sha512(pad(0x5c) + m)
  return m[:32]

def crypto_auth_hmacsha512_verify(a, m, k):
  return crypto_verify_32(a, crypto_auth_hmacsha512(m, k))
