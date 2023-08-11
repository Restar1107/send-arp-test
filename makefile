LDLIBS=-lpcap

all: send-arp-test


main.o: mac.h ip.h ethhdr.h arphdr.h get_my_ip.h get_my_mac.h main.cpp

arphdr.o: mac.h ip.h arphdr.h arphdr.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

ip.o: ip.h ip.cpp

get_my_mac.o: get_my_mac.h get_my_mac.cpp

get_my_ip.o: get_my_ip.h get_my_ip.cpp

mac.o : mac.h mac.cpp

send-arp-test: main.o arphdr.o ethhdr.o ip.o mac.o get_my_ip.o get_my_mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f send-arp-test *.o
