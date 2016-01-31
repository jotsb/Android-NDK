#include "detect.h"

int main(int argc, char **argv) {
	uint8_t *src_mac, *dst_mac, *data;
	struct ip send_iphdr, *recv_iphdr;
  	struct icmp send_icmphdr, *recv_icmphdr;
  	struct addrinfo hints, *res;
	struct sockaddr_in *ipv4;
	struct sockaddr_ll device;
  	struct ifreq ifr;
	struct sockaddr from;
	socklen_t fromlen;
	double dt;
	void *tmp;
	int c, i, status, datalen, frame_length, sendsd, recvsd, bytes, *ip_flags, timeout, trycount, trylim, done;
	char *interface, *src_ip, *target_ip, *rec_ip, *rec_mac, *dst_ip, *temp;

	src_mac = allocate_ustrmem (ETHER_ADDR_LEN);
	dst_mac = allocate_ustrmem (ETHER_ADDR_LEN);
	data = allocate_ustrmem (IP_MAXPACKET);
	interface = allocate_strmem (40);
	src_ip = allocate_strmem(INET_ADDRSTRLEN);
	temp = allocate_strmem(INET_ADDRSTRLEN);
	dst_ip = allocate_strmem(INET_ADDRSTRLEN);
	target_ip = allocate_strmem(INET_ADDRSTRLEN);
	ip_flags = allocate_intmem(4);

	if(argc < 2) {
		fprintf(stderr, "1. Too Few Arguments\n");
		fprintf(stderr, "Option -%c requires an argument.\n", optopt);
        fprintf(stderr, "[USAGE] => %s -i \"[wlan0 or etho0]\" \n", argv[0]);
        return 1;
	} else {
		while((c = getopt (argc, argv, "i:")) != -1) {
            switch(c) {
                case 'i':
                    interface = optarg;
                    break;
                case '?':
                    if(optopt == 'i') {
                        fprintf(stderr, "Option -%c requires an argument.\n", optopt);
                        fprintf(stderr, "[USAGE] => %s -i \"[wlan0 or etho0]\" \n", argv[0]);
                    } else if (isprint (optopt)) {
                        fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                    } else {
                        fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
                    }
                    return 1;
            }
        }
	}

	sendsd = create_raw_socket(ETH_P_ALL);
	memcpy(src_mac, get_mac_addr(sendsd, interface), ETHER_ADDR_LEN);

	// Find interface index from interface name and store index in
	// struct sockaddr_ll device, which will be used as an argument of sendto().
	memset (&device, 0, sizeof (device));
	if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
		perror ("2. if_nametoindex() failed to obtain interface index \n");
		exit (EXIT_FAILURE);
	}
	fprintf (stderr, "3. Index for interface %s is %i\n", interface, device.sll_ifindex);

	 // Set destination MAC address: you need to fill these out
	dst_mac[0] = 0xff;
	dst_mac[1] = 0xff;
	dst_mac[2] = 0xff;
	dst_mac[3] = 0xff;
	dst_mac[4] = 0xff;
	dst_mac[5] = 0xff;

	src_ip = get_ip_addr(sendsd, interface);
	strcpy(temp, src_ip);
	submit_log("SRC IP [%s]", src_ip);
	//target_ip = get_target_ip(src_ip);
	//strcpy(src_ip, get_ip_addr(sendsd, interface)); //Source IPv4 address
	strcpy(target_ip, get_target_ip(temp)); // Destination IPv4 address
	submit_log("TARGET IP [%s]", target_ip);

	// Fill out hints for getaddrinfo().
	memset (&hints, 0, sizeof (struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = hints.ai_flags | AI_CANONNAME;

	// Resolve target using getaddrinfo().
	if ((status = getaddrinfo (target_ip, NULL, &hints, &res)) != 0) {
		fprintf (stderr, "4. getaddrinfo() failed: %s\n", gai_strerror (status));
		exit (EXIT_FAILURE);
	}
	ipv4 = (struct sockaddr_in *) res->ai_addr;
	tmp = &(ipv4->sin_addr);
	if (inet_ntop (AF_INET, tmp, dst_ip, INET_ADDRSTRLEN) == NULL) {
		status = errno;
		fprintf (stderr, "5. inet_ntop() failed. Error message: %s\n", strerror (status));
		exit (EXIT_FAILURE);
	}
	freeaddrinfo (res);

	// Fill out sockaddr_ll.
	device.sll_family = AF_PACKET;
	memcpy (device.sll_addr, src_mac, 6);
	device.sll_halen = 6;

	// ICMP data
	datalen = 4;
	data[0] = 'T';
	data[1] = 'e';
	data[2] = 's';
	data[3] = 't';

	// IPv4 header

	// IPv4 header length (4 bits): Number of 32-bit words in header = 5
	send_iphdr.ip_hl = IP4_HDRLEN / sizeof (uint32_t);

	// Internet Protocol version (4 bits): IPv4
	send_iphdr.ip_v = 4;

	// Type of service (8 bits)
	send_iphdr.ip_tos = 0;

	// Total length of datagram (16 bits): IP header + ICMP header + ICMP data
	send_iphdr.ip_len = htons (IP4_HDRLEN + ICMP_HDRLEN + datalen);

	// ID sequence number (16 bits): unused, since single datagram
	send_iphdr.ip_id = htons (0);

	// Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram

	// Zero (1 bit)
	ip_flags[0] = 0;

	// Do not fragment flag (1 bit)
	ip_flags[1] = 0;

	// More fragments following flag (1 bit)
	ip_flags[2] = 0;

	// Fragmentation offset (13 bits)
	ip_flags[3] = 0;

	send_iphdr.ip_off = htons ((ip_flags[0] << 15)
	                  + (ip_flags[1] << 14)
	                  + (ip_flags[2] << 13)
	                  +  ip_flags[3]);

	// Time-to-Live (8 bits): default to maximum value
	send_iphdr.ip_ttl = 255;

	// Transport layer protocol (8 bits): 1 for ICMP
	send_iphdr.ip_p = IPPROTO_ICMP;

	// Source IPv4 address (32 bits)
	if ((status = inet_pton (AF_INET, src_ip, &(send_iphdr.ip_src))) != 1) {
		fprintf (stderr, "6. inet_pton() failed. Status: %d > Error message: %s\n", status, strerror (status));
		exit (EXIT_FAILURE);
	}

	// Destination IPv4 address (32 bits)
	if ((status = inet_pton (AF_INET, dst_ip, &(send_iphdr.ip_dst))) != 1) {
		fprintf (stderr, "7. inet_pton() failed. Status: %d > Error message: %s\n", status, strerror (status));
		exit (EXIT_FAILURE);
	}

	// IPv4 header checksum (16 bits): set to 0 when calculating checksum
	send_iphdr.ip_sum = 0;
	send_iphdr.ip_sum = checksum ((uint16_t *) &send_iphdr, IP4_HDRLEN);

	return 0;
}

uint16_t checksum (uint16_t *addr, int len) {
  int count = len;
  register uint32_t sum = 0;
  uint16_t answer = 0;

  // Sum up 2-byte values until none or only one byte left.
  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }

  // Add left-over byte, if any.
  if (count > 0) {
    sum += *(uint8_t *) addr;
  }

  // Fold 32-bit sum into 16 bits; we lose information by doing this,
  // increasing the chances of a collision.
  // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  // Checksum is one's compliment of sum.
  answer = ~sum;

  return (answer);
}

char* get_target_ip(char *src_ip) {
	char *target_ip_adr;
	char *ip;
	int i = 0;
	char *array[4];

	ip = strtok(src_ip, ".");
	while(ip != NULL){
		array[i] = ip;
		fprintf(stderr, "%s.", array[i]);
		i++;
		ip = strtok(NULL, ".");
	}
	fprintf(stderr, "\n");

	target_ip_adr = allocate_strmem(INET_ADDRSTRLEN);

	sprintf(target_ip_adr, "%s.%s.%s.%d", array[0], array[1], array[2], TARGET_IP);
	TARGET_IP++;

	submit_log("8. target_ip selected [%s] \n", target_ip_adr);

	return target_ip_adr;
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


/*void send_packet(eth_header *ethernet, arp_header *arp, char *interface) {
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
}*/

int create_raw_socket(int socket_type) {
	int raw;

	if((raw = socket(PF_PACKET, SOCK_RAW, htons(socket_type))) < 0) {
		submit_log("9. [%s]\n","Socket(): failed to get socket descriptor for using ioctl()");
		exit(EXIT_FAILURE);
	}

	return raw;
}

uint8_t* get_mac_addr(int socket, char *interface) {
	uint8_t *src_mac;
	struct ifreq ifr;

	memset (&ifr, 0, sizeof (ifr));
	bzero(&ifr, sizeof(ifr));

	src_mac = allocate_ustrmem(ETHER_ADDR_LEN);

	strncpy((char *)ifr.ifr_name, interface, IFNAMSIZ);

	if((ioctl(socket, SIOCGIFHWADDR, &ifr)) == -1) {
		submit_log("10. create_raw_socket(): [%s]\n","Error getting HW ADDR");
		exit(EXIT_FAILURE);
	}
	memcpy (src_mac, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN * sizeof(uint8_t));

	print_mac_addr(src_mac);

	return src_mac;
}

void print_mac_addr(uint8_t *mac) {
	int i;
	fprintf(stderr, "MAC ADDR: ");
	for (i=0; i<5; i++) {
    	fprintf (stderr, "%02x:", mac[i]);
  	}
  	fprintf (stderr, "%02x\n", mac[5]);
}

char* get_ip_addr(int socket, char *interface) {
	char *src_ip;
	struct ifreq ifr;

	memset (&ifr, 0, sizeof (ifr));
	bzero(&ifr, sizeof(ifr));

	src_ip = allocate_strmem(INET_ADDRSTRLEN);

	strncpy((char *)ifr.ifr_name, interface, IFNAMSIZ);

	if((ioctl(socket, SIOCGIFADDR, &ifr)) == -1) {
		submit_log("11. get_ip_addr(): [%s]\n","Error getting IP ADDR");
		exit(EXIT_FAILURE);
	}

	strcpy(src_ip, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

	
	submit_log("12. IP ADDR: %s\n", src_ip);
	return src_ip;
}

// Allocate memory for an array of unsigned chars.
uint8_t * allocate_ustrmem (int len){
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "13. ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (uint8_t));
    return (tmp);
  } else {
    fprintf (stderr, "14. ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
    exit (EXIT_FAILURE);
  }
}

// Allocate memory for an array of chars.
char * allocate_strmem (int len) {
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "15. ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (char *) malloc (len * sizeof (char));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (char));
    return (tmp);
  } else {
    fprintf (stderr, "16. ERROR: Cannot allocate memory for array allocate_strmem().\n");
    exit (EXIT_FAILURE);
  }
}

// Allocate memory for an array of ints.
int* allocate_intmem (int len){
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "17. ERROR: Cannot allocate memory because len = %i in allocate_intmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (int *) malloc (len * sizeof (int));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (int));
    return (tmp);
  } else {
    fprintf (stderr, "18. ERROR: Cannot allocate memory for array allocate_intmem().\n");
    exit (EXIT_FAILURE);
  }
}

int submit_log(char *msgType, char *string) {
	__android_log_print(ANDROID_LOG_DEBUG, DEBUG_TAG, msgType, string);
	//printf(msgType, string);
	return 0;
}

int submit_log_i(char *msgType, int value) {
	__android_log_print(ANDROID_LOG_DEBUG, DEBUG_TAG, msgType, value);
	//printf(msgType, string);
	return 0;
}