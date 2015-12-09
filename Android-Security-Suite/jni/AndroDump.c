/* Header for class com_example_android_ndk_example_NDKMethods*/
#include "AndroDump.h"


#define DEBUG_TAG "\n[ANDROID_SECURITY_SUITE] ===> LIBPCAP_DEBUGGING ======> "

struct sniff_packet *cap_packet;

// Check all the headers in the Ethernet frame
void pkt_callback(u_char *args,const struct pcap_pkthdr *pkt_hdr,const u_char* packet) {
	static int count = 1;

    u_int16_t type = handle_ethernet(args, pkt_hdr, packet);

    if(type == ETHERTYPE_IP) {
        fprintf(stderr, "[%d] Packet type = [%s]\n", count, "IP");
        handle_IP(args, pkt_hdr, packet);
    } else if (type == ETHERTYPE_ARP) {
        fprintf(stderr, "[%d] Packet type = [%s]\n", count, "ARP");
    } else if (type == ETHERTYPE_REVARP) {
        fprintf(stderr, "[%d] Packet type = [%s]\n", count, "RARP");
    }

    count++;
}

u_int16_t handle_ethernet (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet){
    u_int caplen = pkthdr->caplen; 
    u_int length = pkthdr->len;
    struct sniff_ethernet *ethernet; 
    u_short ether_type;

    if(caplen < ETHER_HDRLEN) {
        submit_log_i("handle_ethernet() => Packet length is less than Ethernet Header Length [%d]\n", caplen);
        return -1;
    }

    // Getting access to Ethernet Packet
    ethernet = (struct sniff_ethernet *)packet;
    ether_type = ntohs(ethernet->ether_type);

    return ether_type;
}

u_char* handle_IP (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet){
    struct my_ip *ip;
    u_int length = pkthdr->len;
    u_int hlen, off, version;
    int len;

    // Jump to IP packet packet + ETHER_HDRLEN
    ip = (struct my_ip *)(packet + ETHER_HDRLEN);
    length -= ETHER_HDRLEN;
    if(length < sizeof(struct my_ip)){
        submit_log_i("handle_IP(): Truncated IP Length = [%d]\n", length);
        return NULL;
    }

    len     = ntohs(ip->ip_len);
    hlen    = IP_HL(ip); // get header length
    version = IP_V(ip); // get IP version number

    //verify version
    if(version != 4) {
        submit_log_i("handle_IP(): Unknown version [%d]\n", version);
        return NULL;
    }

    // verify the header length
    if(hlen < 5) {
        submit_log_i("handle_IP(): Bad Header length [%d]\n", hlen);
        return NULL;
    }

    if(length < len) {
        submit_log_i("handle_IP(): Truncated IP Packet - [%d] bytes missing \n", len - length);
    }

    //cap_packet->ip = ip;

    // Ensure that the first fragment is present
    off = ntohs(ip->ip_off);
    if((off & 0x1fff) == 0) {
        // Do something with the first IP fragment
    }

    /* determine protocol */    
    switch(ip->ip_p) {
        case IPPROTO_TCP:
            submit_log("handle_IP(): Protocol: [%s]\n", "TCP");
            handle_TCP(args, pkthdr, packet);
            break;
        case IPPROTO_UDP:
            submit_log("handle_IP(): Protocol: [%s]\n", "UDP");
            handle_UDP(args, pkthdr, packet);
            return;
        case IPPROTO_ICMP:
            submit_log("handle_IP(): Protocol: [%s]\n", "TCMP");
            handle_ICMP(args, pkthdr, packet);
            return;
        case IPPROTO_IP:
            submit_log("handle_IP(): Protocol: [%s]\n", "IP");
            return;
        default:
            submit_log("handle_IP(): Protocol: [%s]\n", "unknown");
            return;
    }
}

u_char* handle_TCP (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet) {
    struct sniff_tcp *tcp;
    struct my_ip *ip;
    struct sniff_ethernet *ethernet;
    int tcp_len, ip_len;
    char *tcp_payload;

    ethernet = (struct sniff_ethernet *)packet;

    ip = (struct my_ip *)(packet + ETHER_HDRLEN);
    ip_len = IP_HL(ip) * 4;

    tcp = (struct sniff_tcp *) (packet + ETHER_HDRLEN + ip_len);
    tcp_len = TH_OFF(tcp) * 4;

    if(tcp_len < 20) {
        submit_log_i("handle_TCP(): Invalid TCP Header length: [%d] bytpes\n", tcp_len);
        return NULL;
    }

    tcp_payload = (char *)(packet + ETHER_HDRLEN + ip_len + tcp_len);

    print_header_info(ethernet, ip, tcp, NULL, tcp_payload);
}

u_char* handle_UDP (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet) {
}

u_char* handle_ICMP (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet) {
}

void print_header_info(struct sniff_ethernet *ethernet, struct my_ip *ip, struct sniff_tcp *tcp, struct udp_hdr *udp, char *payload) {
    int payload_size;
    FILE *fp;

    if(ethernet == NULL || ip == NULL) {
        submit_log("print_header_info(): Invalid Call: [%s]\n", "Ethernet OR IP packet cannot be null");
    }

    fp = fopen("/data/app/android-security-suite/capture", "a+");

    print_ip_header(fp, ip);

    if(tcp != NULL) {
        payload_size = ntohs(ip->ip_len) - ((IP_HL(ip)*4) + (TH_OFF(tcp)*4));
        print_tcp_header(fp, tcp);
    } else if(udp != NULL) {
    }

    fclose(fp);
}

void print_ip_header (FILE  *fp, struct my_ip *iph) {
    fprintf(fp, "\n");
    fprintf(fp, "IP Header\n");
    fprintf(fp, "   |-IP Version        : %d\n",                        iph->ip_vhl);
    fprintf(fp, "   |-IP Header Lenght  : %d DWORDS or %d Bytes\n",     (IP_HL(iph)), ((IP_HL(iph))*4));
    fprintf(fp, "   |-Type Of Service   : %d\n",                        iph->ip_tos);
    fprintf(fp, "   |-IP Total Length   : %d Bytes(Size of Packet)\n",  iph->ip_len);
    fprintf(fp, "   |-Identification    : %d\n",                        iph->ip_id);
    fprintf(fp, "   |-TTL               : %d\n",                        iph->ip_ttl);
    fprintf(fp, "   |-Protocol          : %d\n",                        iph->ip_p);
    fprintf(fp, "   |-Checksum          : %d\n",                        ntohs(iph->ip_sum));
    fprintf(fp, "   |-Source IP         : %s\n",                        inet_ntoa(iph->ip_src) );
    fprintf(fp, "   |-Destination IP    : %s\n",                        inet_ntoa(iph->ip_dst) );
}

void print_tcp_header(FILE *fp, struct sniff_tcp *tcph) {
    fprintf(fp, "   |\n");
    fprintf(fp, "   |-TCP HEADER\n");
    fprintf(fp, "       |-Source Port           : %d\n",        ntohs(tcph->th_sport));
    fprintf(fp, "       |-Destination Port      : %d\n",        ntohs(tcph->th_dport));
    fprintf(fp, "       |-Sequence Number       : %u\n",        tcph->th_seq);
    fprintf(fp, "       |-Acknowledge Number    : %u\n",        tcph->th_ack);
    fprintf(fp, "       |-Urgent Flag           : %d\n",        (unsigned int)TH_URG);
    fprintf(fp, "       |-Acknowledgement Flag  : %d\n",        (unsigned int)TH_ACK);
    fprintf(fp, "       |-Push Flag             : %d\n",        (unsigned int)TH_PUSH);
    fprintf(fp, "       |-Reset Flag            : %d\n",        (unsigned int)TH_RST);
    fprintf(fp, "       |-Synchronise Flag      : %d\n",        (unsigned int)TH_SYN);
    fprintf(fp, "       |-Finish Flag           : %d\n",        (unsigned int)TH_FIN);
    fprintf(fp, "       |-Window                : %d\n",        ntohs(tcph->th_win));
    fprintf(fp, "       |-Checksum              : %d\n",        ntohs(tcph->th_sum));
    fprintf(fp, "       |-Urgent Pointer        : %d\n",        ntohs(tcph->th_urp));
}

void print_payload(FILE *fp, const char *payload, int payload_size) {

}

int main(int argc, char **argv) {

	char *dev; // Network Device
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *nic_descr;
    const u_char *packet;
    struct pcap_pkthdr pkt_hdr;     // defined in pcap.h
    int loop_ret; 

    cap_packet = malloc(sizeof(sniff_packet));

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

	// Close the connection
	pcap_close(nic_descr);

	return 0;
}


int submit_log(char *msgType, char *string) 
{
	__android_log_print(ANDROID_LOG_DEBUG, DEBUG_TAG, msgType, string);
	//printf(msgType, string);
	return 0;
}

int submit_log_i(char *msgType, int value) 
{
	__android_log_print(ANDROID_LOG_DEBUG, DEBUG_TAG, msgType, value);
	//printf(msgType, string);
	return 0;
}
