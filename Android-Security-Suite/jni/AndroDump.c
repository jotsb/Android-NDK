/* Header for class com_example_android_ndk_example_NDKMethods*/
#include "AndroDump.h"

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <time.h> 


#define DEBUG_TAG "\n[ANDROID_SECURITY_SUITE] ===> LIBPCAP_DEBUGGING ======> "

// Check all the headers in the Ethernet frame
void pkt_callback(u_char *args,const struct pcap_pkthdr *pkt_hdr,const u_char* packet) {
	static int count = 1;
	submit_log("pkt_callback(): [%s]\n", "Running this function");

	//Print out the header information
		printf("Packet length: %d\n",pkt_hdr->len);
    	printf("Ethernet Address Length: %d\n",ETHER_HDRLEN);

	fprintf(stdout,"%d.. ",count);
	fflush(stdout);
	count++;
	
}

int main(int argc, char **argv) {

	char *dev; // Network Device
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *nic_descr;
    const u_char *packet;
    struct pcap_pkthdr pkt_hdr;     // defined in pcap.h
    int loop_ret; 

	// find the first NIC that is up and sniff packets from it
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		submit_log("pcap_lookupdev => errbuf: [%s]\n", errbuf);
		exit(1);
	}
	submit_log("Device: [%s]\n", dev);

	// open device for reading
	nic_descr = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);
	if (nic_descr == NULL) {
		submit_log("pcap_open_live() => errbuf: [%s] \n", errbuf);
		exit(1);
	}
	submit_log("pcap_open_live(): [%s]\n", "Running this function");

	loop_ret = pcap_loop(nic_descr, -1, pkt_callback, NULL);

	submit_log_i("pcap_loop(): loop_ret = [%d]\n", loop_ret);

	// capture a single packet
	//packet = pcap_next(nic_descr, &pkt_hdr);
	//if(packet == NULL) {
	//	submit_log("pcap_next() => errbuf: [%s] \n", "Packet capture failed");
	//	exit(1);
	//}

	// Close the connection
	pcap_close(nic_descr);

	return 0;
}



/*u_int16_t handle_ethernet (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    	u_int caplen = pkthdr->caplen;
    	u_int length = pkthdr->len;
    	struct ether_header *eptr;  //net/ethernet.h 
    	u_short ether_type;

    	if (caplen < ETHER_HDRLEN)
    	{
        	submit_log("Packet length less than ethernet header length\n", "");
        	return -1;
    	}

    	// Start with the Ethernet header... 
    	eptr = (struct ether_header *) packet;
    	ether_type = ntohs(eptr->ether_type);

    	// Print SOURCE DEST TYPE LENGTH fields
   		fprintf(stdout,"ETH: ");
    	fprintf(stdout,"%s ", ether_ntoa((struct ether_addr*)eptr->ether_shost));
    	fprintf(stdout,"%s ",ether_ntoa((struct ether_addr*)eptr->ether_dhost));

    	// Check to see if we have an IP packet 
    	if (ether_type == ETHERTYPE_IP)
    	{
        	fprintf(stdout,"(IP)");
    	}
		else  if (ether_type == ETHERTYPE_ARP)
    	{
        	fprintf(stdout,"(ARP)");
    	}
		else  if (eptr->ether_type == ETHERTYPE_REVARP)
    	{
        	fprintf(stdout,"(RARP)");
    	}
		else 
		{
        	fprintf(stdout,"(?)");
    	}
    	fprintf(stdout," %d\n",length);

    	return ether_type;
}

// This function will parse the IP header and print out selected fields of interest
u_char* handle_IP (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    	const struct my_ip* ip;
    	u_int length = pkthdr->len;
    	u_int hlen,off,version;
    	int len;

    	// Jump past the Ethernet header 
    	ip = (struct my_ip*)(packet + sizeof(struct ether_header));
    	length -= sizeof(struct ether_header); 

    	// make sure that the packet is of a valid length 
    	if (length < sizeof(struct my_ip))
    	{
        	fprintf(stderr,"Truncated IP %d",length);
        	return NULL;
    	}

    	len     = ntohs(ip->ip_len);
    	hlen    = IP_HL(ip); 	// get header length 
    	version = IP_V(ip);	// get the IP version number

    	// verify version 
    	if(version != 4)
    	{
      		fprintf(stderr,"Unknown version %d\n",version);
      		return NULL;
    	}

    	// verify the header length 
    	if(hlen < 5 )
    	{
        	fprintf(stderr,"Bad header length %d \n", hlen);
    	}

    	// Ensure that we have as much of the packet as we should 
    	if (length < len)
        	printf("\nTruncated IP - %d bytes missing\n",len - length);

    	// Ensure that the first fragment is present
    	off = ntohs(ip->ip_off);
    	if ((off & 0x1fff) == 0 ) 	// i.e, no 1's in first 13 bits 
    	{				// print SOURCE DESTINATION hlen version len offset 
        	fprintf(stdout,"IP: ");
        	fprintf(stdout,"%s ", inet_ntoa(ip->ip_src));
        	fprintf(stdout,"%s %d %d %d %d\n", inet_ntoa(ip->ip_dst), hlen,version,len,off);
    	}

    	switch(ip->ip_p) 
		{
			case IPPROTO_TCP:
				handle_TCP(args, pkthdr, packet);
				break;
		}

    	return NULL;
}

u_char* handle_TCP (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
	const struct sniff_tcp *tcp;
	const struct my_ip* ip;
	const char *payload, *tcp_payload;
	unsigned short sport, dport;
	int size_ip, size_tcp;
	
	return NULL;
}*/

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
