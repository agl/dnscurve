from util import xor, randombytes
from verify import verify16, verify32
from salsa20 import stream_salsa20, streamxor_salsa20
from poly1305 import onetimeauth_poly1305, onetimeauth_poly1305_verify
from hash import hash_sha512, auth_hmacsha512, auth_hmacsha512_verify
from curve25519 import smult_curve25519, smult_base_curve25519


def secretbox_salsa20hmacsha512(m, n, k):
  s = stream_salsa20(len(m) + 32, n, k)
  c = xor(m, s[32:])
  a = auth_hmacsha512(c, s[:32])
  return a + c

def secretbox_salsa20hmacsha512_open(c, n, k):
  if len(c) < 32: raise ValueError('Too short for Salsa20HMACSHA512 box')
  s = stream_salsa20(32, n, k)
  if not auth_hmacsha512_verify(c[:32], c[32:], s):
    raise ValueError('Bad authenticator for Salsa20HMACSHA512 box')
  s = stream_salsa20(len(c), n, k)
  return xor(c[32:], s[32:])


def box_curve25519salsa20hmacsha512_keypair():
  sk = randombytes(32)
  pk = smult_curve25519_base(sk)
  return (pk, sk)

def box_curve25519salsa20hmacsha512(m, n, pk, sk):
  k = hash_sha512(smult_curve25519(sk, pk))[:32]
  return secretbox_salsa20hmacsha512(m, n, k)

def box_curve25519salsa20hmacsha512_open(c, n, pk, sk):
  k = hash_sha512(smult_curve25519(sk, pk))[:32]
  return secretbox_salsa20hmacsha512_open(c, n, k)
