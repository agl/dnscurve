def read(f):
  length = ''
  while len(length) < 16:
    c = f.read(1)
    if c == ':':
      break
    if c not in '0123456789':
      raise ValueError('Invalid netstring input')
    length += c

  if len(length) == 16:
    raise ValueError('Invalid netstring input')

  length = int(length)
  data = f.read(length)
  f.read(1)  # chomp ','
  return data

def write(f, s):
  f.write('%d:' % len(s))
  f.write(s)
  f.write(',')
