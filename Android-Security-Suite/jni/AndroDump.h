/* Header for class com_example_android_ndk_example_NDKMethods */
#undef __cplusplus
#undef _GNU_SOURCE

// NDK Header Files
#include <jni.h>
#include <android/log.h>
/*
// Regular C Header Files
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <ctype.h>
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
*/




#ifndef _Included_AndroDump
#define _Included_AndroDump
#ifdef __cplusplus
extern "C" {
#endif

//JNIEXPORT jstring JNICALL ava_com_example_android_1ndk_1example_NDKMethods_set_1msg
//  (JNIEnv *, jclass, jstring);


// tcpdump header (ether.h) defines ETHER_HDRLEN) 
#ifndef ETHER_HDRLEN 
#define ETHER_HDRLEN 14
#endif

int submit_log(char *msgType, char *string);

/*void pkt_callback(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
u_int16_t handle_ethernet (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
u_char* handle_IP (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
u_char* handle_TCP (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);*/


/*
 * Structure of an internet header, stripped of all options.
 *
 * This is taken directly from the tcpdump source
 *
 * We declare ip_len and ip_off to be short, rather than u_short
 * pragmatically since otherwise unsigned comparisons can result
 * against negative integers quite easily, and fail in subtle ways.
 */
/*struct my_ip {
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
	struct	in_addr ip_src,ip_dst;	// source and dest address *
};

// TCP header

struct sniff_tcp {
        u_short th_sport;               // source port 
        u_short th_dport;               // destination port 
        u_int th_seq;                 // sequence number 
        u_int th_ack;                 // acknowledgement number 
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
};*/

#ifdef __cplusplus
}
#endif
#endif
