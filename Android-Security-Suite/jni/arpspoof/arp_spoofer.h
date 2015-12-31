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
#include <pcap.h>

//#include <netinet/ip.h>
//#include <arpa/inet.h>
//#include <netinet/tcp.h>
//#include <netinet/ip_icmp.h>


// ethernet headers are always exactly 14 bytes [1] 
#undef ETHER_HDRLEN
#define ETHER_HDRLEN 14

// Ethernet addresses are 6 bytes
#undef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN  6

// Ethernet header 
typedef struct sniff_ethernet {
        u_char ether_dhost[ETHER_ADDR_LEN];     // Destination host address 
        u_char ether_shost[ETHER_ADDR_LEN];     // Source host address 
        u_short ether_type;                     // IP? ARP? RARP? etc 
}eth_header;


#define ARP_REQUEST 1   // ARP Request              
#define ARP_REPLY 2     // ARP Reply                
typedef struct arp_hdr { 
    u_int16_t htype;    // Hardware Type            
    u_int16_t ptype;    // Protocol Type            
    u_char hlen;        // Hardware Address Length  
    u_char plen;        // Protocol Address Length  
    u_int16_t oper;     // Operation Code           
    u_char sha[6];      // Sender hardware address  
    u_char spa[4];      // Sender IP address        
    u_char tha[6];      // Target hardware address  
    u_char tpa[4];      // Target IP address       
}arp_header; 

eth_header* create_eth_header(char* ether_shost, char* ether_dhost, int ether_type);
arp_header* create_arp_header(char* src_mac, char* src_ip, char* dest_mac, char* dest_ip, int arp_type);
void send_packet(eth_header *ethernet, arp_header *arp);