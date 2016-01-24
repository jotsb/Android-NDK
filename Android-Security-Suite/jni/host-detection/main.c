#include "detect.h"

int main(int argc, char **argv) {

	return 0;
}

eth_header* create_eth_header(char* ether_shost, char* ether_dhost, int ether_type) {
	eth_header *ethernet;
	ethernet = (eth_header *)malloc(sizeof(struct sniff_ethernet));

	// Fill Ethernet Header
	memcpy(ethernet->ether_shost, (void *)ether_aton(ether_shost), 6);
	memcpy(ethernet->ether_dhost, (void *)ether_aton(ether_dhost), 6);
	ethernet->ether_type = htons(ether_type);

	return ethernet;
}

arp_header* create_arp_header(char* src_mac, char* src_ip, char* dest_mac, 
	char* dest_ip, int arp_type) {
	arp_header *arp;
	in_addr_t temp;

	arp = (arp_header *)malloc(sizeof(struct arp_hdr));
	
	// Fill the ARP Header
	arp->htype 	= htons(ARPHRD_ETHER);
	arp->ptype 	= htons(ETHERTYPE_IP);
	arp->hlen 	= 6;
	arp->plen 	= 4;
	arp->oper 	= htons(arp_type);
	memcpy(arp->sha, (void *)ether_aton(src_mac), 6);
	temp 		= inet_addr(src_ip);
	memcpy(arp->spa, &temp, 4);
	memcpy(arp->tha, (void *)ether_aton(dest_mac), 6);
	temp 		= inet_addr(dest_ip);
	memcpy(arp->tpa, &temp, 4);

	return arp;
}

void send_packet(eth_header *ethernet, arp_header *arp, char *interface) {
	struct sockaddr_ll sll;
	struct ifreq ifr;
	int bytes;

	memset (&sll, 0, sizeof (sll));
	memset (&ifr, 0, sizeof (ifr));

	bzero(&sll, sizeof(sll));
	bzero(&ifr, sizeof(ifr));

	strncpy((char *)ifr.ifr_name, interface, IFNAMSIZ);
	//snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);

	if((ioctl(RAW, SIOCGIFINDEX, &ifr)) == -1) {
		submit_log("[%s]\n","Error getting Interface index");
		exit(EXIT_FAILURE);
	}

	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;
	sll.sll_protocol = htons(ETH_P_ALL);
	sll.sll_halen = ETHER_ADDR_LEN;
	memcpy(sll.sll_addr, arp->tha, ETHER_ADDR_LEN);

	PKT_LEN = sizeof(eth_header) + sizeof(arp_header); // Packet Length
	PACKET 	= (unsigned  char *)malloc(PKT_LEN); // Allocate Memory for the Packet
	memcpy(PACKET, ethernet, sizeof(eth_header)); // First Copy Ethernet Header
	memcpy(PACKET + sizeof(eth_header), arp, sizeof(arp_header)); // Next copy ARP Packet after the Ethernet Packet
	if((bytes = sendto(RAW, PACKET, PKT_LEN, 0, (struct sockaddr *)&sll, sizeof(sll))) < 0) {
		submit_log("[%s]\n","Error Sending Packet");
	} else {
		submit_log("[%s]\n", "Packet Sent Successfully");
	}

	free(ethernet);
	free(arp);
	free(PACKET);
}

int create_raw_socket(int socket_type) {
	int raw;

	if((raw = socket(PF_PACKET, SOCK_RAW, htons(socket_type))) < 0) {
		submit_log("[%s]\n","Socket(): failed");
		exit(EXIT_FAILURE);
	}

	return raw;
}

char* get_mac_addr(int socket, char *interface) {
	uint8_t *src_mac;
	char *mac;
	struct ifreq ifr;

	memset (&ifr, 0, sizeof (ifr));
	bzero(&ifr, sizeof(ifr));

	src_mac = allocate_ustrmem(ETHER_ADDR_LEN);
	mac = allocate_strmem(MAC_ADDR_STRLEN);

	strncpy((char *)ifr.ifr_name, interface, IFNAMSIZ);

	if((ioctl(socket, SIOCGIFHWADDR, &ifr)) == -1) {
		submit_log("create_raw_socket(): [%s]\n","Error getting HW ADDR");
		exit(EXIT_FAILURE);
	}
	memcpy (src_mac, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN * sizeof(uint8_t));

	sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x", src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);

	submit_log("Interface: %s\n", interface);
	submit_log("MAC ADDR: %s\n", mac);

	return mac;
	//print_mac_addr(src_mac);
}

char* get_ip_addr(int socket, char *interface) {
	char *src_ip;
	struct ifreq ifr;

	memset (&ifr, 0, sizeof (ifr));
	bzero(&ifr, sizeof(ifr));

	src_ip = allocate_strmem(INET_ADDRSTRLEN);

	strncpy((char *)ifr.ifr_name, interface, IFNAMSIZ);

	if((ioctl(socket, SIOCGIFADDR, &ifr)) == -1) {
		submit_log("create_raw_socket(): [%s]\n","Error getting IP ADDR");
		exit(EXIT_FAILURE);
	}

	strcpy(src_ip, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

	
	submit_log("IP ADDR: %s\n", src_ip);
}

// Allocate memory for an array of unsigned chars.
uint8_t * allocate_ustrmem (int len){
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (uint8_t));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
    exit (EXIT_FAILURE);
  }
}

// Allocate memory for an array of chars.
char * allocate_strmem (int len) {
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (char *) malloc (len * sizeof (char));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (char));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
    exit (EXIT_FAILURE);
  }
}