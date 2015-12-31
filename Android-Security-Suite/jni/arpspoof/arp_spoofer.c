#include "arp_spoofer.h"

eth_header* create_eth_header(char* ether_shost, char* ether_dhost, int ether_type) {
	eth_header *ethernet;
	ethernet = (eth_header *)malloc(sizeof(struct sniff_ethernet));

	return ethernet;
}

arp_header* create_arp_header(char* src_mac, char* src_ip, char* dest_mac, char* dest_ip, int arp_type) {
	arp_header *arp;
	arp = (arp_header *)malloc(sizeof(struct arp_hdr));

	return arp;
}

void send_packet(eth_header *ethernet, arp_header *arp) {

}

int main(int argc, char **argv) {
	return 0;
}