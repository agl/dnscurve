from util import xor, randombytes
from verify import crypto_verify_16, crypto_verify_32
from salsa20 import crypto_stream_salsa20, crypto_stream_salsa20_xor
from poly1305 import crypto_onetimeauth_poly1305, crypto_onetimeauth_poly1305_verify
from hash import crypto_hash_sha512, crypto_auth_hmacsha512, crypto_auth_hmacsha512_verify
from curve25519 import crypto_smult_curve25519, crypto_smult_curve25519_base


def crypto_secretbox_salsa20hmacsha512(m, n, k):
  s = crypto_stream_salsa20(len(m) + 32, n, k)
  c = xor(m, s[32:])
  a = crypto_auth_hmacsha512(c, s[:32])
  return a + c

def crypto_secretbox_salsa20hmacsha512_open(c, n, k):
  if len(c) < 32: raise ValueError('Too short for Salsa20HMACSHA512 box')
  s = crypto_stream_salsa20(32, n, k)
  if not crypto_auth_hmacsha512_verify(c[:32], c[32:], s):
    raise ValueError('Bad authenticator for Salsa20HMACSHA512 box')
  s = crypto_stream_salsa20(len(c), n, k)
  return xor(c[32:], s[32:])


def crypto_box_curve25519salsa20hmacsha512_keypair():
  sk = randombytes(32)
  pk = crypto_smult_curve25519_base(sk)
  return (pk, sk)

def crypto_box_curve25519salsa20hmacsha512(m, n, pk, sk):
  k = crypto_hash_sha512(crypto_smult_curve25519(sk, pk))[:32]
  return crypto_secretbox_salsa20hmacsha512(m, n, k)

def crypto_box_curve25519salsa20hmacsha512_open(c, n, pk, sk):
  k = crypto_hash_sha512(crypto_smult_curve25519(sk, pk))[:32]
  return crypto_secretbox_salsa20hmacsha512_open(c, n, k)
