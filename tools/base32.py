def encode(s):
  k = '0123456789abcdefghijklmnopqrstuv'

  v = 0
  vbits = 0
  output = []

  for c in s:
    v |= ord(c) << vbits
    vbits += 8

    while vbits >= 5:
      output.append(k[v & 31])
      v >>= 5
      vbits -= 5

  if vbits:
    output.append(k[v])

  return ''.join(output)


def decode(s):
  v = 0
  vbits = 0
  output = []

  for c in s.lower():
    if c >= '0' and c <= '9':
      u = ord(c) - ord('0')
    elif c >= 'a' and c <= 'v':
      u = ord(c) - ord('a') + 10
    else:
      raise ValueError('Invalid base-32 input')

    v |= u << vbits
    vbits += 5

    if vbits >= 8:
      output.append(chr(v & 255))
      v >>= 8
      vbits -= 8

  if vbits >= 5 or v:
    raise ValueError('Invalid base-32 input')

  return ''.join(output)
