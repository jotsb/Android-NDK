// NDK Header Files
#include <jni.h>
#include <android/log.h>

// Regular C Header Files
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <sys/stat.h>

// Network Header Files
#include <netinet/ip.h>
#include <netinet/if_ether.h> 
#include <net/ethernet.h>
#include <netinet/ether.h> 
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pcap.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>


// default snap length (maximum bytes per packet to capture)
#undef SNAP_LEN
#define SNAP_LEN 1518

// ethernet headers are always exactly 14 bytes [1] 
#undef ETHER_HDRLEN
#define ETHER_HDRLEN 14

// Ethernet addresses are 6 bytes
#undef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN  6

// The data padding length of the ICMP packet
#undef MTU
#define MTU 1400

#define DEBUG_TAG "\n[ANDROID_SECURITY_SUITE] ===> LIBPCAP_DEBUGGING ======> "

#define DIRECTORY_LOC "/storage/emulated/0/com.ndk.android-security-suite"
#define CAPTURE_FILE "/storage/emulated/0/com.ndk.android-security-suite/capture"

// Ethernet header 

struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; // Destination host address 
    u_char ether_shost[ETHER_ADDR_LEN]; // Source host address 
    u_short ether_type; // IP? ARP? RARP? etc 
};

struct my_header {
    struct in_addr ip_src;
    struct in_addr ip_dst;
    int is_tcp;
    int is_udp;
    int is_icmp;
    int is_ip;
    int is_arp;
    u_int pkt_len; //Total Packet size
    u_short sport; // source port 
    u_short dport; // destination port 
    u_char th_flags; // TCP flags
    unsigned char type; // ICMP Protocol Type (request/reply)
    u_char sha[6]; // Sender hardware address  
    u_char spa[4]; // Sender IP address        
    u_char tha[6]; // Target hardware address  
    u_char tpa[4]; // Target IP address       
};

// IP Header

struct my_ip {
    u_int8_t ip_vhl; // header length, version 
#define IP_V(ip) (((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip) ((ip)->ip_vhl & 0x0f)
    u_int8_t ip_tos; // type of service 
    u_int16_t ip_len; // total length 
    u_int16_t ip_id; // identification 
    u_int16_t ip_off; // fragment offset field 
#define IP_DF 0x4000   // dont fragment flag 
#define IP_MF 0x2000   // more fragments flag
#define IP_OFFMASK 0x1fff  // mask for fragmenting bits 
    u_int8_t ip_ttl; // time to live 
    u_int8_t ip_p; // protocol 
    u_int16_t ip_sum; // checksum 
    struct in_addr ip_src, ip_dst; // source and dest address 
};

// TCP header

struct sniff_tcp {
    u_short th_sport; // source port 
    u_short th_dport; // destination port 
    u_int th_seq; // sequence number 
    u_int th_ack; // acknowledgement number 
    u_char th_offx2; // data offset, rsvd 
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win; // window 
    u_short th_sum; // checksum 
    u_short th_urp; // urgent pointer 
};

// UDP Header 

struct udp_hdr {
    u_short uh_sport; // source port 
    u_short uh_dport; // destination port
    u_short uh_ulen; // datagram length 
    u_short uh_sum; // datagram checksum
};

// ICMP_ECHO/ICMP_ECHO_REPLY prototype

struct icmp_hdr {
    unsigned char type;
    unsigned char code;
    unsigned short checksum;
    unsigned short identifier;
    unsigned short sequence;
};

#define ARP_REQUEST 1   // ARP Request              
#define ARP_REPLY 2     // ARP Reply                

struct arp_hdr {
    u_int16_t htype; // Hardware Type            
    u_int16_t ptype; // Protocol Type            
    u_char hlen; // Hardware Address Length  
    u_char plen; // Protocol Address Length  
    u_int16_t oper; // Operation Code           
    u_char sha[6]; // Sender hardware address  
    u_char spa[4]; // Sender IP address        
    u_char tha[6]; // Target hardware address  
    u_char tpa[4]; // Target IP address       
};


FILE *fp, *fp_summary;
struct my_header *summary;
static int pkt_count = 1;

//
int init_dir();

//
int init_file();

// Submits android logs, takes in string msg
int submit_log(char *msgType, char *string);

// Submits android logs, takes in int value
int submit_log_i(char *msgType, int value);

// find the first NIC that is up and sniff packets from it
char* get_device();

// Starts setting up the packet capturing based on the filter
void* pcap_setup(char *filter);

// initialize my header structure with default values
struct my_header* init_header();

// Handles captured packets
void pkt_callback(u_char *args, const struct pcap_pkthdr *pkt_hdr, const u_char* packet);

// Handles Ethernet packets and returns the message type
u_int16_t handle_ethernet(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);

// Handles ARP packets
u_char* handle_arp(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);

// Handles IP packets
u_char* handle_IP(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);

// Handles TCP packets
u_char* handle_TCP(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);

// Handles UDP packets
u_char* handle_UDP(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);

// Handles ICMP packets
u_char* handle_ICMP(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);

// Handles printing of the ARP packet header information
//void print_arp_header_info(struct sniff_ethernet *ethernet, );

// Handles printing of the packet header information
void print_header_info(struct sniff_ethernet *ethernet, struct arp_hdr *arp, struct my_ip *ip, struct sniff_tcp *tcp, struct udp_hdr *udp, struct icmp_hdr *icmp, char *payload);

// Prints Header Summary
void print_header_summary();

// Prints ARP Header Info
void print_arp_header(FILE *fp, struct arp_hdr *arp);

// Prints Ethernet Header Info to a file
void print_ethernet_header(FILE *fp, struct sniff_ethernet *eth);

// Prints IP Header info to a file
void print_ip_header(FILE *fp, struct my_ip *iph);

// Prints TCP Header info to a file
void print_tcp_header(FILE *fp, struct sniff_tcp *tcp);

// Prints UDP Header info to a file
void print_udp_header(FILE *fp, struct udp_hdr *udph);

// Print ICMP Header info to a file
void print_icmp_header(FILE *fp, struct icmp_hdr *icmp);

// Prints TCP or UDP Payload to a file
void print_payload(FILE *fp, const char *payload, int size);