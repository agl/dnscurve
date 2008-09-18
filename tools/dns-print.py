import sys
import dns

if __name__ == '__main__':
  packet = sys.stdin.read()
  dns.dns_print(packet)
