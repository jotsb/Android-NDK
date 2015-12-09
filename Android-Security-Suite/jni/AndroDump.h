/* Header for class com_example_android_ndk_example_NDKMethods */
#undef __cplusplus
#undef _GNU_SOURCE

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


#ifndef _Included_AndroDump
#define _Included_AndroDump
#ifdef __cplusplus
extern "C" {
#endif


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


typedef struct _sniff_packet sniff_packet;
struct _sniff_packet {
        struct sniff_ethernet   *ethernet;      // store Ethernet Packet
        struct my_ip            *ip;            // store IP Packet
        struct sniff_tcp        *tcp;           // store TCP Packet
        struct UPD_hr           *upd;           // store UDP Packet
        const char              *payload;       // store the Payload
};

// Ethernet header 
struct sniff_ethernet {
        u_char ether_dhost[ETHER_ADDR_LEN];     // Destination host address 
        u_char ether_shost[ETHER_ADDR_LEN];     // Source host address 
        u_short ether_type;                     // IP? ARP? RARP? etc 
};

// IP Header
struct my_ip {
	u_int8_t	ip_vhl;		// header length, version 
        #define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
        #define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
	u_int8_t	ip_tos;		// type of service 
	u_int16_t	ip_len;		// total length 
	u_int16_t	ip_id;		// identification 
	u_int16_t	ip_off;		// fragment offset field 
        #define	IP_DF 0x4000			// dont fragment flag 
        #define	IP_MF 0x2000			// more fragments flag
        #define	IP_OFFMASK 0x1fff		// mask for fragmenting bits 
	u_int8_t	ip_ttl;		// time to live 
	u_int8_t	ip_p;		// protocol 
	u_int16_t	ip_sum;		// checksum 
	struct	in_addr ip_src,ip_dst;	// source and dest address 
};

// TCP header
struct sniff_tcp {
        u_short th_sport;               // source port 
        u_short th_dport;               // destination port 
        u_int th_seq;                   // sequence number 
        u_int th_ack;                   // acknowledgement number 
        u_char  th_offx2;               // data offset, rsvd 
        #define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 // window 
        u_short th_sum;                 // checksum 
        u_short th_urp;                 // urgent pointer 
};

// UDP Header 
struct udp_hdr {
        u_short uh_sport;               // source port 
        u_short uh_dport;               // destination port
        u_short uh_ulen;                // datagram length 
        u_short uh_sum;                 // datagram checksum
};

// ICMP_ECHO/ICMP_ECHO_REPLY prototype
struct icmp_echo {
        unsigned char type;
        unsigned char code;
        unsigned short checksum;
        unsigned short identifier;
        unsigned short sequence;
        char data[MTU];                 // we're going to send data MTU bytes at a time
};



// Submits android logs, takes in string msg
int submit_log(char *msgType, char *string);

// Submits android logs, takes in int value
int submit_log_i(char *msgType, int value);



// Handles captured packets
void pkt_callback(u_char *args,const struct pcap_pkthdr *pkt_hdr,const u_char* packet);

// Handles Ethernet packets and returns the message type
u_int16_t handle_ethernet (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);

// Handles IP packets
u_char* handle_IP (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);

// Handles TCP packets
u_char* handle_TCP (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);

// Handles UDP packets
u_char* handle_UDP (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);

// Handles ICMP packets
u_char* handle_ICMP (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);

// Handles printing of the packet header information
void print_header_info(struct sniff_ethernet *ethernet, struct my_ip *ip, struct sniff_tcp *tcp, struct udp_hdr *udp, char *payload);

// Prints IP Header info to a file
void print_ip_header (FILE  *fp, struct my_ip *iph);

// Prints TCP Header info to a file
void print_tcp_header(FILE *fp, struct sniff_tcp *tcp);

// Prints TCP or UDP Payload to a file
void print_payload(FILE *fp, const char *payload, int payload_size);


#ifdef __cplusplus
}
#endif
#endif
