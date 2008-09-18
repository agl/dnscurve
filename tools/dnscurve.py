import base32

def dnscurve_getpubkey(name):
  for s in name:
    if len(s) == 54 and s[:3].lower() == 'uz5':
      try:
        return base32.decode(s[3:] + '0')
      except ValueError, e:
        pass
  return None


def dnscurve_encode_queryname(nonce, box, pubkey, zone):
  if len(nonce) != 8:
    raise ValueError('Invalid nonce')
  if len(pubkey) != 32 or ord(pubkey[31]) >= 128:
    raise ValueError('Invalid public key')

  data = base32.encode(nonce + box)
  output = chunk(data, 50)
  output.append('x1a' + base32.encode(pubkey)[:51])
  output.extend(zone)

  return output

def dnscurve_decode_queryname(name):
  output = []

  for s in name:
    if len(s) > 50: break
    output.append(s)

  if len(s) != 54 or s[:3].lower() != 'x1a':
    raise ValueError('Not a DNSCurve query')

  key = base32.decode(s[3:] + '0')
  r = base32.decode(''.join(output))
  if r < 8: raise ValueError('Not a DNSCurve query')

  return (key, r[:8], r[8:])


def dnscurve_encode_rdata(nonce, box):
  if len(nonce) != 8: raise ValueError('Invalid nonce')
  data = nonce + box
  return chunk(data, 255)

def dnscurve_decode_rdata(rdata):
  data = ''.join(rdata)
  if len(data) < 8: raise ValueError('Invalid DNSCurve response')
  return (data[:8], data[8:])


# Split 's' into a list of strings with length no greater than 'n'.
def chunk(s, n):
  return [s[i:i+n] for i in range(0, len(s), n)]
