import struct
import binascii

qtypes = {1: 'A',
          2: 'NS',
          5: 'CNAME',
          6: 'SOA',
          12: 'PTR',
          15: 'MX',
          16: 'TXT'}

qclasses = {1: 'IN'}

def dns_name_read(rest, p):
  output = []
  firstcompress = None

  while True:
    b = ord(rest[0])
    if b == 0:
      rest = rest[1:]
      break
    elif b < 64:
      output.append(rest[1:1+b])
      output.append('.')
      rest = rest[1+b:]
      continue
    elif b >= 192:
      b2 = ord(rest[1])
      pos = 256 * (b - 192) + b2
      if firstcompress is None:
        firstcompress = rest[2:]
      rest = p[pos:]
      continue
    else:
      raise ValueError('Bad DNS name')

  if firstcompress is not None:
    return (''.join(output), firstcompress)
  return (''.join(output), rest)

def dns_query_read(rest, p):
  (name, rest) = dns_name_read(rest, p)
  (qtype, qclass) = struct.unpack('>HH', rest[:4])
  return ((name, qtypes.get(qtype, '??'), qclasses.get(qclass, '??')), rest[4:])

def dns_result_read(rest, p):
  (name, rest) = dns_name_read(rest, p)
  (qtype, qclass, ttl, rdlen) = struct.unpack('>HHIH', rest[:10])
  rest = rest[10:]
  data = rest[:rdlen]
  return ((name, qtypes.get(qtype, '??'), qclasses.get(qclass, '??'), ttl, data), rest[rdlen:])

def dns_print(p):
  (id, f1, f2, nquery, nans, nauth, nadd) = struct.unpack('>HBBHHHH', p[:12])

  flags = []
  if f1 & 0x80:
    flags.append('response')
  else:
    flags.append('query')

  if f1 & 4:
    flags.append('authoriative')
  if f1 & 2:
    flags.append('truncated')
  if f1 & 1:
    flags.append('recursion-requested')

  if f2 & 0x80:
    flags.append('recursion-avail')

  rcode = f2 & 15;
  errors = {0: 'Success',
            1: 'Format error',
            2: 'Server failure',
            3: 'Name error',
            4: 'Not implemented',
            5: 'Refused'}

  status = errors.get(rcode, 'Unknown')

  print ';; DNS packet:', ' '.join(flags)
  print ';; Status:', status
  print ';; QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d' % (nquery, nans, nauth, nadd)
  print

  print ';; QUESTION SECTION'
  rest = p[12:]
  for n in range(nquery):
    (query, rest) = dns_query_read(rest, p)
    print ';%s\t\t\t%s\t%s' % query

  for (section, count) in [('ANSWER', nans), ('AUTHORITY', nauth),
                           ('ADDITIONAL', nadd)]:
    print
    print ';; %s SECTION' % section
    for n in range(count):
      ((name, type, qclass, ttl, data), rest) = dns_result_read(rest, p)
      print '%s\t\t%d\t%s\t%s\t%s' % (name, ttl, type, qclass, binascii.b2a_hex(data))

def dns_build_query(host):
  output = []

  output.append('\x42\x76\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00')

  name = host.split('.')
  for n in name:
    output.append(chr(len(n)))
    output.append(n)
  output.append(chr(0))

  output.append('\x00\x01')
  output.append('\x00\x01')

  return ''.join(output)
