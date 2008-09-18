import sys

import nacl
import netstring

def main():
  (pk, sk) = nacl.box_curve25519salsa20hmacsha512_keypair()
  netstring.write(sys.stdout, sk)
  netstring.write(sys.stdout, pk)

if __name__ == '__main__':
  main()
