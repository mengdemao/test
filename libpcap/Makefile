all:test_pcap_recv test_pcap_send
	@echo "compile success"

test_pcap_recv:recv.cpp Makefile
	g++ recv.cpp -o test_pcap_recv -lpcap -Wall -Wextra -Wpedantic

test_pcap_send:send.cpp Makefile
	g++ send.cpp -o test_pcap_send -lpcap -Wall -Wextra -Wpedantic