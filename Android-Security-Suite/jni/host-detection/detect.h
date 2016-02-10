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
#include <netdb.h>            // struct addrinfo
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <net/if.h> 
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <linux/if_ether.h> 
#include <linux/if_packet.h>
#include <netinet/ether.h> 
#include <netinet/in.h>       // IPPROTO_ICMP, INET_ADDRSTRLEN
#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)
#include <netinet/ip_icmp.h>  // struct icmp, ICMP_ECHO
#include <pcap.h>
#include <arpa/inet.h>


// ethernet headers are always exactly 14 bytes [1] 
#undef ETHER_HDRLEN
#define ETHER_HDRLEN 14

// Ethernet addresses are 6 bytes
#define ETHER_ADDR_LEN  6

#define IP4_HDRLEN 20  // IPv4 header length
#define ICMP_HDRLEN 8  // ICMP header length for echo request, excludes data

#define INET_ADDR_STRLEN 16
#define MAC_ADDR_STRLEN 18

#define TRY_LIMIT 4

#define TIMEOUT 1

#define DEBUG_TAG "\n[ANDROID_SECURITY_SUITE] ===> LIBPCAP_DEBUGGING ======> "

#define TRUE 1

#define CONFIG_FILE_LOC "/storage/emulated/0/com.ndk.android-security-suite/arp-exec"

// Ethernet header 
typedef struct sniff_ethernet {
        u_char ether_dhost[ETHER_ADDR_LEN];     // Destination host address 
        u_char ether_shost[ETHER_ADDR_LEN];     // Source host address 
        u_short ether_type;                     // IP? ARP? RARP? etc 
}eth_header;


// Global Variables
char *MY_IP_ADDRS;
char *MY_MAC_ADDRS;

char MY_IP_ADDR[INET_ADDR_STRLEN] = "192.168.0.12";
char MY_MAC_ADDR[MAC_ADDR_STRLEN] = "8c:3a:e3:99:24:0b";

char VICTIM_IP_ADDR[INET_ADDR_STRLEN] = "192.168.0.50";
//char VICTIM_MAC_ADDR[MAC_ADDR_STRLEN] = "c0:ee:fb:5a:ce:5a";
char VICTIM_MAC_ADDR[MAC_ADDR_STRLEN] = "44:8a:5b:9e:00:9e";

char ROUTER_IP_ADDR[INET_ADDR_STRLEN] = "192.168.0.1";
char ROUTER_MAC_ADDR[MAC_ADDR_STRLEN] = "50:39:55:63:17:b4";

char BROADCAST_MAC_ADDR[MAC_ADDR_STRLEN] = "00:00:00:00:00:00";

int TARGET_IP = 1;
int SEQ_NUM = 1;
int FINAL_TARGET_IP = 254;

int PKT_LEN;
unsigned char *PACKET;

// Function Definitions
int create_raw_socket(int socket_type);
int submit_log(char *msgType, char *string);
int submit_log_i(char *msgType, int value);
void print_mac_addr(uint8_t *mac);
uint8_t* get_mac_addr(int socket, char *interface);
char* get_ip_addr(int socket, char *interface);
char* get_target_ip(char *src_ip);
uint16_t ipv4_checksum (uint16_t *addr, int len);
uint16_t icmp4_checksum (struct icmp icmphdr, uint8_t *payload, int payloadlen);
struct ip build_ip_hdr(int datalen, char *src_ip, char *dst_ip);
struct icmp build_icmp_hdr(uint8_t *data, int datalen);
uint8_t* build_ether_frame(int frame_length, uint8_t *src_mac, struct ip send_iphdr, struct icmp send_icmphdr, uint8_t *data, int datalen);
void *capture_packets(void *arg);

//P.D. Buchan (pdbuchan@yahoo.com)
uint8_t *allocate_ustrmem (int len);
char * allocate_strmem (int len);
int* allocate_intmem (int len);