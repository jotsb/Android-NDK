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
    struct udp_hdr *udp;
    struct my_ip *ip;
    struct sniff_ethernet *ethernet;
    int udp_len, ip_len;
    char *udp_payload;
    u_int caplen = pkthdr->caplen; 

    ethernet = (struct sniff_ethernet *)packet;

    ip = (struct my_ip *)(packet + ETHER_HDRLEN);
    ip_len = IP_HL(ip) * 4;

    caplen -= (ETHER_HDRLEN + ip_len);

    udp = (struct udp_hdr *)(packet + ETHER_HDRLEN + ip_len);
    udp_len = sizeof(struct udp_hdr);

    if(caplen < udp_len) {
        submit_log_i("handle_UDP(): Invalid UDP Header length: [%d] bytpes\n", caplen);
        return NULL;
    }

    udp_payload = (char *)(packet + ETHER_HDRLEN + ip_len + udp_len);

    print_header_info(ethernet, ip, NULL, udp, udp_payload);
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

    if(tcp != NULL) {
        payload_size = ntohs(ip->ip_len) - ((IP_HL(ip)*4) + (TH_OFF(tcp)*4));

        fprintf(fp, "\n***********************TCP Packet*************************\n");
        
        print_ethernet_header(fp, ethernet);
        print_ip_header(fp, ip);
        print_tcp_header(fp, tcp);
        
        fprintf(fp, " IP Header\n");
        print_payload(fp, (const char *)ip, (IP_HL(ip)*4));
        
        fprintf(fp, " TCP HEADER\n");
        print_payload(fp, (const char *)tcp, (TH_OFF(tcp)*4));
        
        fprintf(fp, " PAYLOAD\n");
        print_payload(fp, payload, payload_size);
    } else if(udp != NULL) {
        payload_size = ntohs(ip->ip_len) - ((IP_HL(ip)*4) + sizeof(struct udp_hdr));
        
        fprintf(fp, "\n***********************UDP Packet*************************\n");
        
        print_ethernet_header(fp, ethernet);
        print_ip_header(fp, ip);
        print_udp_header(fp, udp);
        
        fprintf(fp, " IP Header\n");
        print_payload(fp, (const char *)ip, (IP_HL(ip)*4));

        fprintf(fp, " UDP HEADER\n");
        print_payload(fp, (const char *)udp, (sizeof(struct udp_hdr)));
        
        fprintf(fp, " PAYLOAD\n");
        print_payload(fp, payload, payload_size);
    }

    fprintf(fp, "\n###########################################################\n");

    fclose(fp);
}

void print_ethernet_header(FILE *fp, struct sniff_ethernet *eth) {
    fprintf(fp, "\n");
    fprintf(fp, " Ethernet Header\n");
    fprintf(fp, "   |-Destination Address   : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",    eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
    fprintf(fp, "   |-Source Address        : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",    eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    fprintf(fp, "   |-Source Address        : %u \n",                               eth->ether_type);
}

void print_ip_header (FILE  *fp, struct my_ip *iph) {
    fprintf(fp, "\n");
    fprintf(fp, " IP Header\n");
    fprintf(fp, "   |-IP Version            : %d\n",                        iph->ip_vhl);
    fprintf(fp, "   |-IP Header Lenght      : %d DWORDS or %d Bytes\n",     (IP_HL(iph)), ((IP_HL(iph))*4));
    fprintf(fp, "   |-Type Of Service       : %d\n",                        iph->ip_tos);
    fprintf(fp, "   |-IP Total Length       : %d Bytes(Size of Packet)\n",  iph->ip_len);
    fprintf(fp, "   |-Identification        : %d\n",                        iph->ip_id);
    fprintf(fp, "   |-TTL                   : %d\n",                        iph->ip_ttl);
    fprintf(fp, "   |-Protocol              : %d\n",                        iph->ip_p);
    fprintf(fp, "   |-Checksum              : %d\n",                        ntohs(iph->ip_sum));
    fprintf(fp, "   |-Source IP             : %s\n",                        inet_ntoa(iph->ip_src) );
    fprintf(fp, "   |-Destination IP        : %s\n",                        inet_ntoa(iph->ip_dst) );
}

void print_tcp_header(FILE *fp, struct sniff_tcp *tcph) {
    fprintf(fp, "\n");
    fprintf(fp, " TCP HEADER\n");
    fprintf(fp, "   |-Source Port           : %d\n",        ntohs(tcph->th_sport));
    fprintf(fp, "   |-Destination Port      : %d\n",        ntohs(tcph->th_dport));
    fprintf(fp, "   |-Sequence Number       : %u\n",        tcph->th_seq);
    fprintf(fp, "   |-Acknowledge Number    : %u\n",        tcph->th_ack);
    fprintf(fp, "   |-Urgent Flag           : %d\n",        (unsigned int)TH_URG);
    fprintf(fp, "   |-Acknowledgement Flag  : %d\n",        (unsigned int)TH_ACK);
    fprintf(fp, "   |-Push Flag             : %d\n",        (unsigned int)TH_PUSH);
    fprintf(fp, "   |-Reset Flag            : %d\n",        (unsigned int)TH_RST);
    fprintf(fp, "   |-Synchronise Flag      : %d\n",        (unsigned int)TH_SYN);
    fprintf(fp, "   |-Finish Flag           : %d\n",        (unsigned int)TH_FIN);
    fprintf(fp, "   |-Window                : %d\n",        ntohs(tcph->th_win));
    fprintf(fp, "   |-Checksum              : %d\n",        ntohs(tcph->th_sum));
    fprintf(fp, "   |-Urgent Pointer        : %d\n",        ntohs(tcph->th_urp));
}

void print_udp_header(FILE *fp, struct udp_hdr *udph) {
    fprintf(fp, "\n");
    fprintf(fp, " UDP HEADER\n");
    fprintf(fp, "   |-Source Port           : %d\n",    ntohs(udph->uh_sport));
    fprintf(fp, "   |-Destination Port      : %d\n",    ntohs(udph->uh_dport));
    fprintf(fp, "   |-UDP Length            : %d\n",    ntohs(udph->uh_ulen));
    fprintf(fp, "   |-UDP Checksum          : %d\n",    ntohs(udph->uh_sum));
}

void print_payload(FILE *fp, const char *data, int size) {
    int i , j;
    for(i=0 ; i < size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            fprintf(fp , "         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    fprintf(fp , "%c",(unsigned char)data[j]); //if its a number or alphabet
                 
                else fprintf(fp , "."); //otherwise print a dot
            }
            fprintf(fp , "\n");
        } 
         
        if(i%16==0) fprintf(fp , "   ");
            fprintf(fp , " %02X",(unsigned int)data[i]);
                 
        if( i==size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++) 
            {
              fprintf(fp , "   "); //extra spaces
            }
             
            fprintf(fp , "         ");
             
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) 
                {
                  fprintf(fp , "%c",(unsigned char)data[j]);
                }
                else
                {
                  fprintf(fp , ".");
                }
            }
             
            fprintf(fp ,  "\n" );
        }
    }
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
