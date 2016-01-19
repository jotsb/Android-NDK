/* Header for class com_example_android_ndk_example_NDKMethods*/
#include "AndroDump.h"

// Check all the headers in the Ethernet frame
void pkt_callback(u_char *args,const struct pcap_pkthdr *pkt_hdr,const u_char* packet) {
	static int count = 1;

    u_int16_t type = handle_ethernet(args, pkt_hdr, packet);
    
    if(type == ETHERTYPE_IP) {
        fprintf(stderr, "[%d] Packet type = [%s]\n", count, "IP");
        handle_IP(args, pkt_hdr, packet);
    } else if (type == ETHERTYPE_ARP) {
        fprintf(stderr, "[%d] Packet type = [%s]\n", count, "ARP");
        handle_arp(args, pkt_hdr, packet);
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

u_char* handle_arp(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet) {
    struct arp_hdr *arp;
    struct sniff_ethernet *ethernet;
    u_int pkt_len = pkthdr->len;

    summary = init_header();
    summary->is_arp = 1;

    ethernet = (struct sniff_ethernet *)packet;

    arp = (struct arp_hdr *)(packet + ETHER_HDRLEN);
    pkt_len -= ETHER_HDRLEN;
    if(pkt_len < sizeof(struct arp_hdr)) {
        submit_log_i("handle_arp(): Truncated ARP Length = [%d]\n", pkt_len);
        return NULL;
    }

    print_header_info(ethernet, arp, NULL, NULL, NULL, NULL, NULL);
}

u_char* handle_IP (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet){
    struct my_ip *ip;
    u_int length = pkthdr->len;
    u_int hlen, off, version;
    int len;

    summary = init_header();
    summary->is_ip = 1;

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



    // Ensure that the first fragment is present
    off = ntohs(ip->ip_off);
    if((off & 0x1fff) == 0) {
        // Do something with the first IP fragment
    }

    summary->ip_src = ip->ip_src;
    summary->ip_dst = ip->ip_dst;   
    summary->pkt_len = pkthdr->caplen;

    /* determine protocol */    
    switch(ip->ip_p) {
        case IPPROTO_TCP:
            submit_log("handle_IP(): Protocol: [%s]\n", "TCP");
            handle_TCP(args, pkthdr, packet);
            break;
        case IPPROTO_UDP:
            submit_log("handle_IP(): Protocol: [%s]\n", "UDP");
            handle_UDP(args, pkthdr, packet);
            break;
        case IPPROTO_ICMP:
            submit_log("handle_IP(): Protocol: [%s]\n", "ICMP");
            handle_ICMP(args, pkthdr, packet);
            break;
        case IPPROTO_IP:
            submit_log("handle_IP(): Protocol: [%s]\n", "IP");
            break;
        default:
            submit_log("handle_IP(): Protocol: [%s]\n", "unknown");
            break;
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

    summary->is_tcp = 1;
    summary->sport = tcp->th_sport;
    summary->dport = tcp->th_dport;
    summary->th_flags = tcp->th_flags;

    tcp_payload = (char *)(packet + ETHER_HDRLEN + ip_len + tcp_len);

    print_header_info(ethernet, NULL, ip, tcp, NULL, NULL, tcp_payload);
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

    summary->is_udp = 1;
    summary->sport = udp->uh_sport;
    summary->dport = udp->uh_dport;

    udp_payload = (char *)(packet + ETHER_HDRLEN + ip_len + udp_len);

    print_header_info(ethernet, NULL, ip, NULL, udp, NULL, udp_payload);
}

u_char* handle_ICMP (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet) {
    struct my_ip *ip;
    struct icmp_hdr *icmp;
    struct sniff_ethernet *ethernet;
    u_int ip_len, icmp_len;
    u_int caplen = pkthdr->caplen; 
    char * icmp_payload;
    const u_char * icmph;

    ethernet = (struct sniff_ethernet *)packet;

    ip = (struct my_ip *)(packet + ETHER_HDRLEN);
    ip_len = IP_HL(ip)*4;

    icmp = (struct icmp_hdr *)(packet + ETHER_HDRLEN + ip_len);
    icmp_len = sizeof(struct icmp_hdr);

    /*caplen -= (ETHER_HDRLEN + ip_len);
    if(caplen < icmp_len) {
        submit_log_i("handle_ICMP(): Invalid ICMP Header length: [%d] bytes\n", icmp_len);
        return NULL;
    }*/

    summary->is_icmp = 1;
    summary->type = icmp->type;

    icmp_payload = (char *)(packet + ETHER_HDRLEN + ip_len + icmp_len);

    print_header_info(ethernet, NULL, ip, NULL, NULL, icmp, icmp_payload);
}

/*void print_arp_header_info(struct sniff_ethernet *ethernet, struct arp_hdr *arp) {
    FILE *fp;

    if(ethernet == NULL || arp == NULL) {
        submit_log("print_arp_header_info(): Invalid Call: [%s]\n", "Ethernet OR ARP packets cannot be null");
        exit(1);
    }
}*/

void print_header_info(struct sniff_ethernet *ethernet, struct arp_hdr*arp, struct my_ip *ip, struct sniff_tcp *tcp, struct udp_hdr *udp, struct icmp_hdr *icmp, char *payload) {
    int payload_size;
    FILE *fp;

    fp = fopen(CAPTURE_FILE, "a");
    fp_summary = fopen("/data/app/android-security-suite/summary", "w");    

    if(ethernet == NULL) {
        submit_log("print_header_info(): Invalid Call: [%s]\n", "Ethernet packet cannot be null");
        exit(250);
    }

    if (ip != NULL) {
        print_ethernet_header(fp, ethernet);
        print_ip_header(fp, ip);

        if(tcp != NULL) {
            //print_header_summary();
            payload_size = ntohs(ip->ip_len) - ((IP_HL(ip)*4) + (TH_OFF(tcp)*4));

            //fprintf(fp, "\n%d: ***********************TCP Packet*************************\n", pkt_count);
            
            print_tcp_header(fp, tcp);
            
            /*fprintf(fp, " IP Header\n");
            print_payload(fp, (const char *)ip, (IP_HL(ip)*4));
            
            fprintf(fp, " TCP HEADER\n");
            print_payload(fp, (const char *)tcp, (TH_OFF(tcp)*4));
            
            fprintf(fp, " PAYLOAD\n");
            print_payload(fp, payload, payload_size);*/
        } else if(udp != NULL) {
            //print_header_summary();
            payload_size = ntohs(ip->ip_len) - ((IP_HL(ip)*4) + sizeof(struct udp_hdr));
            
            //fprintf(fp, "\n%d: ***********************UDP Packet*************************\n", pkt_count);
            
            print_udp_header(fp, udp);
            
            /*fprintf(fp, " IP Header\n");
            print_payload(fp, (const char *)ip, (IP_HL(ip)*4));

            fprintf(fp, " UDP HEADER\n");
            print_payload(fp, (const char *)udp, (sizeof(struct udp_hdr)));
            
            fprintf(fp, " PAYLOAD\n");
            print_payload(fp, payload, payload_size);*/
        } else if (icmp != NULL) {
            //print_header_summary();
            payload_size = ntohs(ip->ip_len) - ((IP_HL(ip)*4) + (sizeof(struct icmp_hdr)));

            //fprintf(fp, "\n%d: ***********************ICMP Packet*************************\n", pkt_count);

            print_icmp_header(fp, icmp);

            /*fprintf(fp, " IP Header\n");
            print_payload(fp, (const char *)ip, (IP_HL(ip)*4));
            
            fprintf(fp, " ICMP HEADER\n");
            print_payload(fp, (const char *)icmp, (sizeof(struct icmp_hdr)));
            
            fprintf(fp, " PAYLOAD\n");
            print_payload(fp, payload, payload_size);*/
        }
    } else if (arp != NULL) {
        //print_header_summary();

        //fprintf(fp, "\n%d: ***********************ARP Packet*************************\n", pkt_count);
        print_ethernet_header(fp, ethernet);
        print_arp_header(fp, arp);

        /*fprintf(fp, " ARP Header\n");
        print_payload(fp, (const char *)arp, sizeof(struct arp_hdr));*/

    } else {
        submit_log("print_header_info(): Invalid Call: [%s]\n", "IP and ARP packets both cannot be null. One of the 2 is required");
        exit(250);
    }

    //fprintf(fp, "\n###########################################################\n");
    fclose(fp);
    fclose(fp_summary);
    pkt_count++;
}

void print_header_summary() {

    if(summary->is_ip == 1) {

        if(summary->is_tcp == 1) {
            fprintf(fp_summary, "[%d]   %s:%d   =>  %s:%d       TCP     Length = %u       Flag = [%d]\n", 
                pkt_count, inet_ntoa(summary->ip_src), ntohs(summary->sport), 
                inet_ntoa(summary->ip_dst), ntohs(summary->dport), summary->pkt_len, 
                (unsigned int)summary->th_flags);

        } else if (summary->is_udp == 1) {
            fprintf(fp_summary, "[%d]   %s:%d   =>  %s:%d       UDP     Length = %u       \n", 
                pkt_count, inet_ntoa(summary->ip_src), ntohs(summary->sport), 
                inet_ntoa(summary->ip_dst), ntohs(summary->dport), summary->pkt_len);

        } else if (summary->is_icmp == 1) {
            fprintf(fp_summary, "[%d]   %s      =>  %s          ICMP    Length = %u       ", 
                pkt_count, inet_ntoa(summary->ip_src), inet_ntoa(summary->ip_dst), summary->pkt_len);
            if((unsigned int)(summary->type) == ICMP_ECHOREPLY){
                fprintf(fp_summary , "[ICMP Echo Reply]\n");
            } else if((unsigned int)(summary->type) == ICMP_ECHO){
                fprintf(fp_summary , "[ICMP Echo Request]\n");
            } else {
                fprintf(fp_summary , "[Type = %u]\n", (unsigned int)summary->type);
            }
        }

    } else if (summary->is_arp == 1) {
        // handle arp printing
    }
}

void print_arp_header(FILE *fp, struct arp_hdr *arp){
    fprintf(fp, " ARP Header,");
    fprintf(fp, "Hardware Type : %s,",      (ntohs(arp->htype) == 1) ? "Ethernet" : "Unknown");
    fprintf(fp, "Protocol Type : %s,",      (ntohs(arp->ptype) == 0x0800) ? "IPV4" : "Unknown");
    fprintf(fp, "Operation : %s,",      (ntohs(arp->oper) == ARP_REQUEST) ? "ARP Request" : "ARP Reply");

    if(ntohs(arp->htype) == 1 && ntohs(arp->ptype) == 0x0800) {
        fprintf(fp, "Sender MAC : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X,",     arp->sha[0], arp->sha[1], arp->sha[2], arp->sha[3], arp->sha[4], arp->sha[5] );
        fprintf(fp, "Target MAC : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X,",     arp->tha[0], arp->tha[1], arp->tha[2], arp->tha[3], arp->tha[4], arp->tha[5] );
        fprintf(fp, "Sender IP  : %d.%d.%d.%d,",                        arp->spa[0], arp->spa[1], arp->spa[2], arp->spa[3] );
        fprintf(fp, "Target IP  : %d.%d.%d.%d" ,                       arp->tpa[0], arp->tpa[1], arp->tpa[2], arp->tpa[3] );
    }
        fprintf(fp, "\n");
}

void print_ethernet_header(FILE *fp, struct sniff_ethernet *eth) {
    u_int16_t type;
    fprintf(fp, "Ethernet Header,");
    fprintf(fp, "Dest MAC Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X,",    eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
    fprintf(fp, "Source MAC Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X,",    eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    fprintf(fp, "Type :");

    type = ntohs(eth->ether_type);

    if(type == ETHERTYPE_IP) {
        fprintf(fp, " %s,", "IP");
    } else if (type == ETHERTYPE_ARP) {
        fprintf(fp, " %s,", "ARP");
    } else if (type == ETHERTYPE_REVARP) {
        fprintf(fp, " %s,", "RARP");
    }
}

void print_ip_header (FILE  *fp, struct my_ip *iph) {
    fprintf(fp, " IP Header,");
    fprintf(fp, "IP Version : %d,",                        IP_V(iph));
    fprintf(fp, "IP Header Length : %d DWORDS or %d Bytes,",     (IP_HL(iph)), ((IP_HL(iph))*4));
    fprintf(fp, "Type Of Service : %d,",                        iph->ip_tos);
    fprintf(fp, "IP Total Length : %d Bytes(Size of Packet),",  iph->ip_len);
    fprintf(fp, "Identification : %d,",                        iph->ip_id);
    fprintf(fp, "TTL : %d,",                        iph->ip_ttl);
    fprintf(fp, "Checksum : %d,",                        ntohs(iph->ip_sum));
    fprintf(fp, "Source IP : %s,",                        inet_ntoa(iph->ip_src) );
    fprintf(fp, "Destination IP : %s,",                        inet_ntoa(iph->ip_dst) );
    fprintf(fp, "Protocol :");

    switch(iph->ip_p) {
        case IPPROTO_TCP:
            fprintf(fp, " %s,", "TCP");
            break;
        case IPPROTO_UDP:
            fprintf(fp, " %s,", "UDP");
            break;
        case IPPROTO_ICMP:
            fprintf(fp, " %s,", "ICMP");
            break;
        case IPPROTO_IP:
            fprintf(fp, " %s,", "IP");
            break;
    }
}

void print_tcp_header(FILE *fp, struct sniff_tcp *tcph) {
    fprintf(fp, " TCP HEADER,");
    fprintf(fp, "Source Port : %d,",        ntohs(tcph->th_sport));
    fprintf(fp, "Destination Port : %d,",        ntohs(tcph->th_dport));
    fprintf(fp, "Sequence Number : %u,",        tcph->th_seq);
    fprintf(fp, "Acknowledge Number : %u,",        tcph->th_ack);
    fprintf(fp, "Flags : %d,",        (unsigned int)tcph->th_flags);
    fprintf(fp, "Urgent Flag : %d,",        (unsigned int)TH_URG);
    fprintf(fp, "Acknowledgement Flag : %d,",        (unsigned int)TH_ACK);
    fprintf(fp, "Push Flag : %d,",        (unsigned int)TH_PUSH);
    fprintf(fp, "Reset Flag : %d,",        (unsigned int)TH_RST);
    fprintf(fp, "Synchronise Flag : %d,",        (unsigned int)TH_SYN);
    fprintf(fp, "Finish Flag : %d,",        (unsigned int)TH_FIN);
    fprintf(fp, "Window : %d,",        ntohs(tcph->th_win));
    fprintf(fp, "Checksum : %d,",        ntohs(tcph->th_sum));
    fprintf(fp, "Urgent Pointer : %d",        ntohs(tcph->th_urp));
        fprintf(fp, "\n");
}

void print_udp_header(FILE *fp, struct udp_hdr *udph) {
    fprintf(fp, " UDP HEADER,");
    fprintf(fp, "Source Port : %d,",    ntohs(udph->uh_sport));
    fprintf(fp, "Destination Port : %d,",    ntohs(udph->uh_dport));
    fprintf(fp, "UDP Length : %d,",    ntohs(udph->uh_ulen));
    fprintf(fp, "UDP Checksum : %d",    ntohs(udph->uh_sum));
        fprintf(fp, "\n");
}

void print_icmp_header(FILE *fp, struct icmp_hdr *icmph){
    fprintf(fp, " ICMP HEADER,");
    fprintf(fp, "Type : ");
    if((unsigned int)(icmph->type) == 11)
    {
        fprintf(fp , " TTL Expired,");
    }
    else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
    {
        fprintf(fp , " ICMP Echo Reply,");
    } else if((unsigned int)(icmph->type) == ICMP_ECHO)
    {
        fprintf(fp , " ICMP Echo Request,");
    }

    fprintf(fp, "Code : %d,",    (unsigned int)icmph->code);
    fprintf(fp, "Checksum : %d",    ntohs(icmph->checksum));
        fprintf(fp, "\n");
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

char* get_device() {
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev;

    dev = pcap_lookupdev(errbuf);
    if(dev == NULL) {
        submit_log("pcap_lookupdev => errbuf: [%s]\n", errbuf);
        return NULL;
    }

    submit_log("Device: [%s]\n", dev);

    return dev;
}

void* pcap_setup(char *filter) {
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    pcap_t *nic_descr;
    int loop_ret;
    bpf_u_int32 mask; //The netmask of our sniffing device
    bpf_u_int32 net; //The IP of our sniffing device 

    dev = get_device();

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) 
    {
        submit_log("Can't get netmask for device: [%s]\n", dev);
        net = 0;
        mask = 0;
        exit(1);
    }

    nic_descr = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);
    if (nic_descr == NULL) {
        submit_log("pcap_open_live() => errbuf: [%s] \n", errbuf);
        exit(1);
    }
    submit_log("pcap_open_live(): [%s]\n", "Running this function");

    if(filter == NULL) {
        // start pcap_loop
        loop_ret = pcap_loop(nic_descr, -1, pkt_callback, NULL);
        submit_log_i("pcap_loop(): loop_ret = [%d]\n", loop_ret);
    } else {
        // setup the filter
        if (pcap_compile(nic_descr, &fp, filter, 0, net) == -1) 
        {          
            submit_log("pcap_setup(): pcap_compile() => Error Calling PCAP_COMPILE() => FILTER = [%s] \n", filter);
            exit(1);
        } 
        
        if (pcap_setfilter(nic_descr, &fp) == -1) 
        {
            submit_log("pcap_setup(): pcap_setfilter() => [%s] \n", "Error Calling PCAP_SETFILTER()");
            exit(1);
        }

        loop_ret = pcap_loop(nic_descr, -1, pkt_callback, NULL);
        submit_log_i("pcap_loop(): loop_ret = [%d]\n", loop_ret);
    }
}

void terminate_pcap() {
}

struct my_header* init_header() {
    struct my_header *my_hdr = malloc(sizeof(struct my_header));
    my_hdr->is_tcp = 0;
    my_hdr->is_udp = 0;
    my_hdr->is_icmp = 0;
    my_hdr->is_ip = 0;
    my_hdr->is_arp = 0;

    return my_hdr;
}

int init_dir() {
    int result;

    result = mkdir(DIRECTORY_LOC, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

    if(result == -1) {
        if(errno == EEXIST) {
            return 0;
        } else {
            submit_log("Failed to create directory [%s]", DIRECTORY_LOC);
            return -1;
        }
    }

    return 0;
}

int init_file() {

    if(init_dir() == 0) {
        fp = fopen(CAPTURE_FILE, "w");
        fp_summary = fopen("/data/app/android-security-suite/summary", "w"); 

        fclose(fp);
        fclose(fp_summary);
    } else {
        exit(1);
    }

    return 0;
}

int main(int argc, char **argv) {

    char *dev; // Network Device
    char *filter = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *nic_descr;
    const u_char *packet;
    struct pcap_pkthdr pkt_hdr;     // defined in pcap.h
    int loop_ret, c, status;

    /*status = remove ("/data/app/android-security-suite/capture");

    if( status == 0 )
      submit_log("[%s] => file deleted successfully.\n","/data/app/android-security-suite/capture");
    else
    {
        submit_log("[%s] => Unable to delete the file\n", "/data/app/android-security-suite/capture");
    }

    status = remove ("/data/app/android-security-suite/summary");

    if( status == 0 )
      submit_log("[%s] => file deleted successfully.\n","/data/app/android-security-suite/summary");
    else
    {
        submit_log("[%s] => Unable to delete the file\n", "/data/app/android-security-suite/summary");
    }*/

    /*if(mkdir("com.ndk.android-security-suite", S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) == 0) {
        fp = fopen("/storage/emulated/legacy/com.ndk.android-security-suite/capture", "w");
        fp_summary = fopen("/data/app/android-security-suite/summary", "w"); 

        fclose(fp);
        fclose(fp_summary);
    }*/

    init_file();

    dev = get_device();

    if(argc < 2) {
        pcap_setup(NULL);
    } else {
        while((c = getopt (argc, argv, "f:")) != -1) {
            switch(c) {
                case 'f':
                    filter = optarg;
                    pcap_setup(filter);
                    break;
                case '?':
                    if(optopt == 'f') {
                        fprintf(stderr, "Option -%c requires an argument.\n", optopt);
                        fprintf(stderr, "[USAGE] => %s -f \"dst port 80\" \n", argv[0]);
                    } else if (isprint (optopt)) {
                        fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                    } else {
                        fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
                    }
                    return 1;
            }
        }
    }

    // Close the connection
    pcap_close(nic_descr);
    submit_log("main(): pcap_close()=> [%s]\n", "Connection closed successfully");

    return 0;
}

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


// kill using "pkill AndroDump"