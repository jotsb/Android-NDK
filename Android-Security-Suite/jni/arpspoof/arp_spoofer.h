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
#include <arpa/inet.h>

//#include <netinet/ip.h>
//#include <netinet/tcp.h>
//#include <netinet/ip_icmp.h>


// ethernet headers are always exactly 14 bytes [1] 
#undef ETHER_HDRLEN
#define ETHER_HDRLEN 14

// Ethernet addresses are 6 bytes
#undef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN  6

#define INET_ADDR_STRLEN 16
#define MAC_ADDR_STRLEN 18

#define DEBUG_TAG "\n[ANDROID_SECURITY_SUITE] ===> LIBPCAP_DEBUGGING ======> "

#define TRUE 1

#define CONFIG_FILE_LOC "/storage/emulated/0/com.ndk.android-security-suite/arp-exec"

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

// Global Variables
char *MY_IP_ADDRS;
char *MY_MAC_ADDRS;

char MY_IP_ADDR[INET_ADDR_STRLEN] = "192.168.0.12";
char MY_MAC_ADDR[MAC_ADDR_STRLEN] = "8c:3a:e3:99:24:0b";

char VICTIM_IP_ADDR[INET_ADDR_STRLEN] = "192.168.0.15";
//char VICTIM_MAC_ADDR[MAC_ADDR_STRLEN] = "c0:ee:fb:5a:ce:5a";
char VICTIM_MAC_ADDR[MAC_ADDR_STRLEN] = "44:8a:5b:9e:00:9e";

char ROUTER_IP_ADDR[INET_ADDR_STRLEN] = "192.168.0.1";
char ROUTER_MAC_ADDR[MAC_ADDR_STRLEN] = "50:39:55:63:17:b4";

char BROADCAST_MAC_ADDR[MAC_ADDR_STRLEN] = "00:00:00:00:00:00";

int RAW;
int PKT_LEN;
unsigned char *PACKET;

// Function Definitions
eth_header* create_eth_header(char* ether_shost, char* ether_dhost, int ether_type);
arp_header* create_arp_header(char* src_mac, char* src_ip, char* dest_mac, char* dest_ip, int arp_type);
void send_packet(eth_header *ethernet, arp_header *arp, char *interface);
int create_raw_socket(int socket_type);
int submit_log(char *msgType, char *string);
int submit_log_i(char *msgType, int value);
void print_mac_addr(uint8_t *mac);

//P.D. Buchan (pdbuchan@yahoo.com)
uint8_t *allocate_ustrmem (int len);
char * allocate_strmem (int len);