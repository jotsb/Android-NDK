#include "detect.h"

int main(int argc, char **argv) {
	uint8_t *src_mac, *dst_mac, *data, *send_ether_frame, *recv_ether_frame;
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
	send_ether_frame = allocate_ustrmem (IP_MAXPACKET);
  	recv_ether_frame = allocate_ustrmem (IP_MAXPACKET);
	data = allocate_ustrmem (IP_MAXPACKET);
	interface = allocate_strmem (40);
	src_ip = allocate_strmem(INET_ADDRSTRLEN);
	temp = allocate_strmem(INET_ADDRSTRLEN);
	dst_ip = allocate_strmem(INET_ADDRSTRLEN);
	target_ip = allocate_strmem(INET_ADDRSTRLEN);
	ip_flags = allocate_intmem(4);
	done = 0;

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

	// Fill out hints for getaddrinfo().
	memset (&hints, 0, sizeof (struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = hints.ai_flags | AI_CANONNAME;

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

	src_ip = get_ip_addr(sendsd, interface);
	submit_log("SRC IP [%s]", src_ip);

	// GET TARGET LOOP STARTS HERE
	for(;;) {
		strcpy(temp, src_ip);
		strcpy(target_ip, get_target_ip(temp)); // Destination IPv4 address
		submit_log("TARGET IP [%s]", target_ip);

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

		send_iphdr = build_ip_hdr(datalen, src_ip, dst_ip);
		send_icmphdr = build_icmp_hdr(data, datalen);
		
		// Fill out ethernet frame header.

		// Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + ICMP header + ICMP data)
		frame_length = ETHER_HDRLEN + IP4_HDRLEN + ICMP_HDRLEN + datalen;

		send_ether_frame = build_ether_frame(frame_length, src_mac, send_iphdr, send_icmphdr, data, datalen);

		// Submit request for a raw socket descriptor to receive packets.
		if ((recvsd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
			perror ("socket() failed to obtain a receive socket descriptor ");
			exit (EXIT_FAILURE);
		}

		// Set maximum number of tries to ping remote host before giving up.
		trylim = 3;
		trycount = 0;

		


		if(TARGET_IP == 254) {
			break; //break the target_ip loop
		}
	}

	return 0;
}

// IPv4 header
struct ip build_ip_hdr(int datalen, char *src_ip, char *dst_ip) {
	struct ip send_iphdr;
	int *ip_flags, status;

	ip_flags = allocate_intmem(4);

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

	return send_iphdr;
}

// ICMP header
struct icmp build_icmp_hdr(uint8_t *data, int datalen) {
	struct icmp send_icmphdr;
	
	// Message Type (8 bits): echo request
	send_icmphdr.icmp_type = ICMP_ECHO;

	// Message Code (8 bits): echo request
	send_icmphdr.icmp_code = 0;

	// Identifier (16 bits): usually pid of sending process - pick a number
	send_icmphdr.icmp_id = htons (1000);

	// Sequence Number (16 bits): starts at 0
	send_icmphdr.icmp_seq = htons (0);

	// ICMP header checksum (16 bits): set to 0 when calculating checksum
	send_icmphdr.icmp_cksum = icmp4_checksum (send_icmphdr, data, datalen);

	return send_icmphdr;
}

// Frame
uint8_t* build_ether_frame(int frame_length, uint8_t *src_mac, struct ip send_iphdr, struct icmp send_icmphdr, uint8_t *data, int datalen) {
	uint8_t *send_ether_frame, *dst_mac;
	send_ether_frame = allocate_ustrmem (IP_MAXPACKET);
	dst_mac = allocate_ustrmem (ETHER_ADDR_LEN);

	 // Set destination MAC address: you need to fill these out
	dst_mac[0] = 0xff;
	dst_mac[1] = 0xff;
	dst_mac[2] = 0xff;
	dst_mac[3] = 0xff;
	dst_mac[4] = 0xff;
	dst_mac[5] = 0xff;

	// Destination and Source MAC addresses
	memcpy (send_ether_frame, dst_mac, 6);
	memcpy (send_ether_frame + 6, src_mac, 6);

	// Next is ethernet type code (ETH_P_IP for IPv4).
	// http://www.iana.org/assignments/ethernet-numbers
	send_ether_frame[12] = ETH_P_IP / 256;
	send_ether_frame[13] = ETH_P_IP % 256;

	// Next is ethernet frame data (IPv4 header + ICMP header + ICMP data).

	// IPv4 header
	memcpy (send_ether_frame + ETHER_HDRLEN, &send_iphdr, IP4_HDRLEN);

	// ICMP header
	memcpy (send_ether_frame + ETHER_HDRLEN + IP4_HDRLEN, &send_icmphdr, ICMP_HDRLEN);

	// ICMP data
	memcpy (send_ether_frame + ETHER_HDRLEN + IP4_HDRLEN + ICMP_HDRLEN, data, datalen);

	return send_ether_frame;
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

// Build IPv4 ICMP pseudo-header and call checksum function.
uint16_t icmp4_checksum (struct icmp icmphdr, uint8_t *payload, int payloadlen) {
  char buf[IP_MAXPACKET];
  char *ptr;
  int chksumlen = 0;
  int i;

  ptr = &buf[0];  // ptr points to beginning of buffer buf

  // Copy Message Type to buf (8 bits)
  memcpy (ptr, &icmphdr.icmp_type, sizeof (icmphdr.icmp_type));
  ptr += sizeof (icmphdr.icmp_type);
  chksumlen += sizeof (icmphdr.icmp_type);

  // Copy Message Code to buf (8 bits)
  memcpy (ptr, &icmphdr.icmp_code, sizeof (icmphdr.icmp_code));
  ptr += sizeof (icmphdr.icmp_code);
  chksumlen += sizeof (icmphdr.icmp_code);

  // Copy ICMP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy Identifier to buf (16 bits)
  memcpy (ptr, &icmphdr.icmp_id, sizeof (icmphdr.icmp_id));
  ptr += sizeof (icmphdr.icmp_id);
  chksumlen += sizeof (icmphdr.icmp_id);

  // Copy Sequence Number to buf (16 bits)
  memcpy (ptr, &icmphdr.icmp_seq, sizeof (icmphdr.icmp_seq));
  ptr += sizeof (icmphdr.icmp_seq);
  chksumlen += sizeof (icmphdr.icmp_seq);

  // Copy payload to buf
  memcpy (ptr, payload, payloadlen);
  ptr += payloadlen;
  chksumlen += payloadlen;

  // Pad to the next 16-bit boundary
  for (i=0; i<payloadlen%2; i++, ptr++) {
    *ptr = 0;
    ptr++;
    chksumlen++;
  }

  return checksum ((uint16_t *) buf, chksumlen);
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