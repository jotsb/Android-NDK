/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

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


#ifdef __cplusplus
}
#endif

#endif /* DNS_SPOOF_H */

