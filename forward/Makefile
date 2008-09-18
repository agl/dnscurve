CFLAGS=-Wall -ggdb -std=c99
TARGETS=forward udpserver dnscurve-keygen dnscurve-test-client

targets: $(TARGETS)

clean:
	rm -f *.o $(TARGETS)

dnscurve-test-client: dnscurve-test-client.o randombytes.o ip_parse.o dns_packet.o base32.o
	gcc $(CFLAGS) -o dnscurve-test-client dnscurve-test-client.o randombytes.o ip_parse.o dns_packet.o base32.o -lnacl

forward: forward.o dns_packet.o base32.o randombytes.o ip_parse.o dns_random.o
	gcc $(CFLAGS) -o forward forward.o dns_packet.o base32.o randombytes.o ip_parse.o dns_random.o -lpthread -lnacl -lrt

udpserver: udpserver.o ip_parse.o
	gcc $(CFLAGS) -o udpserver udpserver.o ip_parse.o

dnscurve-keygen: dnscurve-keygen.o base32.o randombytes.o
	gcc $(CFLAGS) -o dnscurve-keygen dnscurve-keygen.o base32.o randombytes.o -lnacl

forward.o: forward.c dns.h
	gcc $(CFLAGS) -c forward.c

dns_packet.o: dns_packet.c base32.h dns.h
	gcc $(CFLAGS) -c dns_packet.c

base32.o: base32.c base32.h
	gcc $(CFLAGS) -c base32.c

randombytes.o: randombytes.c
	gcc $(CFLAGS) -c randombytes.c

ip_parse.o: ip_parse.c
	gcc $(CFLAGS) -c ip_parse.c

dns_random.o: ip_parse.c
	gcc $(CFLAGS) -c dns_random.c

udpserver.o: udpserver.c
	gcc $(CFLAGS) -c udpserver.c

dnscurve-keygen.o: dnscurve-keygen.c
	gcc $(CFLAGS) -c dnscurve-keygen.c

dnscurve-test-client.o: dnscurve-test-client.c
	gcc $(CFLAGS) -c dnscurve-test-client.c
