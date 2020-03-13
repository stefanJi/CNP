all: arp ping

arp: src/arp.cpp src/include/log.h
	mkdir -p build/
	g++ -I src/include src/arp.cpp -o build/arp

ping: src/ping.cpp src/include/log.h
	mkdir -p build/
	g++ -I src/include src/ping.cpp -o build/ping

