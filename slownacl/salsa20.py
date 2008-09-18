import struct
from util import xor

__all__ = ['stream_salsa20', 'stream_salsa20_xor']

def rotate(x, n):
  x &= 0xffffffff
  return ((x << n) | (x >> (32 - n))) & 0xffffffff

def step(s, i, j, k, r):
  s[i] ^= rotate(s[j] + s[k],r)

def quarterround(s, i0, i1, i2, i3):
  step(s, i1, i0, i3, 7)
  step(s, i2, i1, i0, 9)
  step(s, i3, i2, i1, 13)
  step(s, i0, i3, i2, 18)

def rowround(s):
  quarterround(s, 0, 1, 2, 3)
  quarterround(s, 5, 6, 7, 4)
  quarterround(s, 10, 11, 8, 9)
  quarterround(s, 15, 12, 13, 14)

def columnround(s):
  quarterround(s, 0, 4, 8, 12)
  quarterround(s, 5, 9, 13, 1)
  quarterround(s, 10, 14, 2, 6)
  quarterround(s, 15, 3, 7, 11)

def doubleround(s):
  columnround(s)
  rowround(s)

def rounds(s, n):
  s1 = list(s)
  while n >= 2:
    doubleround(s1)
    n -= 2
  for i in range(16): s[i] = (s[i] + s1[i]) & 0xffffffff

o = struct.unpack('<4I', 'expand 32-byte k')

def block(i, n, k):
  i = (i & 0xffffffff, i >> 32)
  s = [0] * 16
  s[::5] = o
  s[1:5] = k[:4]
  s[6:10] = n + i
  s[11:15] = k[4:]
  rounds(s, 20)
  return struct.pack('<16I', *s)

def stream_salsa20(l, n, k):
  output = []
  n = struct.unpack('<2I', n)
  k = struct.unpack('<8I', k)
  for i in xrange(0, l, 64):
    output.append(block(i // 64, n, k))
  return ''.join(output)[:l]

def stream_salsa20_xor(m, n, k):
  return xor(m, stream_salsa20(len(m), n, k))
