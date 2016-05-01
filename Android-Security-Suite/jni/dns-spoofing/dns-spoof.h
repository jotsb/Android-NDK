/* 
 * File:   dns-spoof.h
 * Author: jb
 *
 * Created on March 30, 2016, 9:39 PM
 */

#ifndef DNS_SPOOF_H
#define DNS_SPOOF_H

#ifdef __cplusplus
extern "C" {
#endif

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
#include <errno.h>
    //#include <features.h>

    // Network Header Files
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h> 
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <linux/if_ether.h> 
#include <linux/if_packet.h>
#include <netinet/ether.h> 
#include <netinet/in.h>
#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)
#include <netinet/udp.h>
#include <pcap.h>
#include <arpa/inet.h>

    //#include <netinet/ip.h>
    //#include <netinet/tcp.h>
    //#include <netinet/ip_icmp.h>


    // ethernet headers are always exactly 14 bytes [1] 
#undef ETHER_HDRLEN
#define ETHER_HDRLEN        14
    // Ethernet addresses are 6 bytes
#undef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN      6
#define IP4_HDRLEN          20       // IPv4 header length
#define INET_ADDR_STRLEN    16
#define MAC_ADDR_STRLEN     18
#define REQUEST_SIZE        100
#define DATAGRAM_SIZE       8192
#define UDP_PKT             17

#define DEBUG_TAG "\n[ANDROID_SECURITY_SUITE] ===> LIBPCAP_DEBUGGING ======> "

#define TRUE 1

    struct sniff_ethernet {
        u_char ether_dhost[ETHER_ADDR_LEN]; // Destination host address 
        u_char ether_shost[ETHER_ADDR_LEN]; // Source host address 
        u_short ether_type; // IP? ARP? RARP? etc 
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

    // UDP Header 

    struct udp_hdr {
        u_short uh_sport; // source port 
        u_short uh_dport; // destination port
        u_short uh_ulen; // datagram length 
        u_short uh_sum; // datagram checksum
    };

    struct dns_response {
        struct DNS_HEADER *_hdr;
        struct dns_query *_query;
        struct RES_RECORD *_response;
    };

    //DNS header

    struct DNS_HEADER {
        unsigned short id;
        unsigned char rd : 1;
        unsigned char tc : 1;
        unsigned char aa : 1;
        unsigned char opcode : 4;
        unsigned char qr : 1;

        unsigned char rcode : 4;
        unsigned char cd : 1;
        unsigned char ad : 1;
        unsigned char z : 1;
        unsigned char ra : 1;

        unsigned short q_count;
        unsigned short ans_count;
        unsigned short auth_count;
        unsigned short add_count;
    };

#pragma pack(push, 1)

    struct R_DATA {
        unsigned short type;
        unsigned short _class;
        unsigned int ttl;
        unsigned short data_len;
    };
#pragma pack(pop)

    struct RES_RECORD {
        unsigned char *name;
        struct R_DATA *resource;
        unsigned char *rdata;
    };

    /* DNS header definition */
    struct dns_hdr {
        char id[2];
        char flags[2];
        char qdcount[2];
        char ancount[2];
        char nscount[2];
        char arcount[2];
    };

    /* DNS query structure */
    struct dns_query {
        char *qname;
        char qtype[2];
        char qclass[2];
    };

    struct my_header {
        struct in_addr ip_src; // Client IP Address
        struct in_addr ip_dst; // DNS Server IP Address
        u_short src_port; // Client application source port
        char* url_query; // URL in the Client Request
        char* request; // URL being spoofed
        char* response; // IP Address to send back 
    };

    struct my_header* header_info; // captured header info


    int submit_log(char *msgType, char *string);
    int submit_log_i(char *msgType, int value);
    char* get_device();
    void* pcap_setup(char *filter);
    struct my_header* init_header();
    void pkt_callback(u_char *args, const struct pcap_pkthdr *pkt_hdr, const u_char* packet);
    u_int16_t handle_ethernet(const struct pcap_pkthdr* pkthdr, const u_char* packet);
    u_char* handle_IP(const struct pcap_pkthdr* pkthdr, const u_char* packet);
    u_char* handle_UDP(const struct pcap_pkthdr* pkthdr, const u_char* packet);
    void handle_DNS(const char* packet);
    char* extract_dns_request(struct dns_query *dnsquery);
    void extract_ip_from_iphdr(struct my_ip* ip);
    struct ip build_ip_hdr();
    struct udp_hdr build_udp_hdr();
    struct dns_response build_dns_answer(struct dns_query *query);
    void build_response_packet(struct dns_query *query);
    uint16_t ipv4_checksum(uint16_t *addr, int len);
    char * allocate_strmem(int len);
    int* allocate_intmem(int len);

#ifdef __cplusplus
}
#endif

#endif /* DNS_SPOOF_H */

