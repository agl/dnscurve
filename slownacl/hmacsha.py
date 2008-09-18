import hashlib
import hmac
from verify import crypto_verify_32

def crypto_auth_hmacsha512(m, k):
  return hmac.new(k, m, hashlib.sha512).digest()

def crypto_auth_hmacsha512_verify(a, m, k):
  return crypto_verify_32(a, crypto_auth_hmacsha512(m, k))
