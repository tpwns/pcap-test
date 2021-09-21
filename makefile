LDLIBS += -lpcap

all: pcap-test

pcap-test: pcap-test.c my-headers.h

clean:
	rm -f pcap-test *.o
