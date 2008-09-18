def crypto_verify_16(a, b):
  if len(a) != 16 or len(b) != 16:
    raise ValueError('Not 16 bytes')
  return a == b

def crypto_verify_32(a, b):
  if len(a) != 32 or len(b) != 32:
    raise ValueError('Not 32 bytes')
  return a == b
