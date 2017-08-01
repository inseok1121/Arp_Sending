all: arp

arp : main.c
	gcc -o arp main.c -lpcap -I/usr/include/pcap -W -Wall

clean:
	rm -f arp
	
