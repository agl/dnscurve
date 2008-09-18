import sys
import dns

if __name__ == '__main__':
  sys.stdout.write(dns.dns_build_query(sys.argv[1], sys.argv[2]))
