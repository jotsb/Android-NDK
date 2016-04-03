/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   dns-spoof.c
 * Author: jb
 *
 * Created on March 30, 2016, 9:38 PM
 */

#include "dns-spoof.h"

char* get_device() {
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev;

    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
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

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
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

    if (filter == NULL) {
        // start pcap_loop
        loop_ret = pcap_loop(nic_descr, -1, pkt_callback, NULL);
        submit_log_i("pcap_loop(): loop_ret = [%d]\n", loop_ret);
    } else {
        // setup the filter
        if (pcap_compile(nic_descr, &fp, filter, 0, net) == -1) {
            submit_log("pcap_setup(): pcap_compile() => Error Calling PCAP_COMPILE() => FILTER = [%s] \n", filter);
            exit(1);
        }

        if (pcap_setfilter(nic_descr, &fp) == -1) {
            submit_log("pcap_setup(): pcap_setfilter() => [%s] \n", "Error Calling PCAP_SETFILTER()");
            exit(1);
        }

        loop_ret = pcap_loop(nic_descr, -1, pkt_callback, NULL);
        submit_log_i("pcap_loop(): loop_ret = [%d]\n", loop_ret);
    }
}

void pkt_callback(u_char *args, const struct pcap_pkthdr *pkt_hdr, const u_char* packet) {
    static int count = 1;

    u_int16_t type = handle_ethernet(args, pkt_hdr, packet);

    if (type == ETHERTYPE_IP) {
        fprintf(stderr, "Packet type = [%s]\n", "IP");
        //handle_IP(args, pkt_hdr, packet);
    } else if (type == ETHERTYPE_ARP) {
        fprintf(stderr, "Packet type = [%s]\n", "ARP");
        //handle_arp(args, pkt_hdr, packet);
    } else if (type == ETHERTYPE_REVARP) {
        fprintf(stderr, "Packet type = [%s]\n", "RARP");
    }

    count++;
}

u_int16_t handle_ethernet(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    u_int caplen = pkthdr->caplen;
    u_int length = pkthdr->len;
    struct sniff_ethernet *ethernet;
    u_short ether_type;

    if (caplen < ETHER_HDRLEN) {
        submit_log_i("handle_ethernet() => Packet length is less than Ethernet Header Length [%d]\n", caplen);
        return -1;
    }

    // Getting access to Ethernet Packet
    ethernet = (struct sniff_ethernet *) packet;
    ether_type = ntohs(ethernet->ether_type);

    return ether_type;
}

u_char* handle_IP(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    struct my_ip *ip;
    u_int length = pkthdr->len;
    u_int hlen, off, version;
    int len;

    // Jump to IP packet packet + ETHER_HDRLEN
    ip = (struct my_ip *) (packet + ETHER_HDRLEN);
    length -= ETHER_HDRLEN;
    if (length < sizeof (struct my_ip)) {
        submit_log_i("handle_IP(): Truncated IP Length = [%d]\n", length);
        return NULL;
    }

    len = ntohs(ip->ip_len);
    hlen = IP_HL(ip); // get header length
    version = IP_V(ip); // get IP version number

    //verify version
    if (version != 4) {
        submit_log_i("handle_IP(): Unknown version [%d]\n", version);
        return NULL;
    }

    // verify the header length
    if (hlen < 5) {
        submit_log_i("handle_IP(): Bad Header length [%d]\n", hlen);
        return NULL;
    }

    if (length < len) {
        submit_log_i("handle_IP(): Truncated IP Packet - [%d] bytes missing \n", len - length);
    }

    // Ensure that the first fragment is present
    off = ntohs(ip->ip_off);
    if ((off & 0x1fff) == 0) {
        // Do something with the first IP fragment
    }

    /* determine protocol */
    switch (ip->ip_p) {
        case IPPROTO_UDP:
            submit_log("handle_IP(): Protocol: [%s]\n", "UDP");
            handle_UDP(args, pkthdr, packet);
            break;
        default:
            submit_log("handle_IP(): Protocol: [%s]\n", "unknown");
            break;
    }
}

u_char* handle_UDP(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    struct udp_hdr *udp;
    struct my_ip *ip;
    struct sniff_ethernet *ethernet;
    int udp_len, ip_len;
    char *dns_pkt;
    u_int caplen = pkthdr->caplen;

    ethernet = (struct sniff_ethernet *) packet;

    ip = (struct my_ip *) (packet + ETHER_HDRLEN);
    ip_len = IP_HL(ip) * 4;

    caplen -= (ETHER_HDRLEN + ip_len);

    udp = (struct udp_hdr *) (packet + ETHER_HDRLEN + ip_len);
    udp_len = sizeof (struct udp_hdr);

    if (caplen < udp_len) {
        submit_log_i("handle_UDP(): Invalid UDP Header length: [%d] bytes\n", caplen);
        return NULL;
    }

    dns_pkt = (char *) (packet + ETHER_HDRLEN + ip_len + udp_len);

    handle_DNS(args, pkthdr, dns_pkt);
}

void handle_DNS(u_char *args, const struct pcap_pkthdr* pkthdr, const char* packet) {

}

/**
 * Extracts the request from a dns query
 * It comes in this format: [3]www[7]example[3]com[0]
 * And it is returned in this: www.example.com
 */
void extract_dns_request(struct dnsquery *dns_query, char *request) {
    unsigned int i, j, k;
    char *curr = dns_query->qname;
    unsigned int size;

    size = curr[0];

    j = 0;
    i = 1;
    while (size > 0) {
        for (k = 0; k < size; k++) {
            request[j++] = curr[i + k];
        }
        request[j++] = '.';
        i += size;
        size = curr[i++];
    }
    request[--j] = '\0';
}

/*
 * Main Function
 */
int main(int argc, char** argv) {
    char *dev, *filter = NULL, *victim_ip = NULL, *interface_name = NULL; // Network Device, Filter
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *nic_descr;
    const u_char *packet;
    struct pcap_pkthdr pkt_hdr; // defined in pcap.h
    int loop_ret, c, status;

    if (argc < 3) {
        fprintf(stderr, "Please use -i for Network Interface \nAND -v for Victim IP Address \nOR -h for help");
    } else {
        while ((c = getopt(argc, argv, "i:v:r:a:h")) != 1) {
            switch (c) {
                case 'i': // device interface
                    interface_name = optarg;
                    break;
                case 'v': // Victim machines IP address
                    victim_ip = optarg;
                    break;
                case 'r': // Domain name you want to spoof
                    break;
                case 'a': // Address you want to send in the answer
                    break;
                case 'h':
                    return EXIT_SUCCESS;
                case '?':
                    return EXIT_FAILURE;
            }
        }
    }

    if ((status = asprintf(&filter, "%s %s", "udp and port 53 and src", victim_ip)) < 0) {
        fprintf(stderr, "Unable to get the Victim IP Address");
    }

    pcap_setup(filter);

    //strcpy(filter, "udp and port 53 and src ");
    //strcpy(filter, victim);

    return (EXIT_SUCCESS);
}

int submit_log(char *msgType, char *string) {
    __android_log_print(ANDROID_LOG_DEBUG, DEBUG_TAG, msgType, string);
    return 0;
}

int submit_log_i(char *msgType, int value) {
    __android_log_print(ANDROID_LOG_DEBUG, DEBUG_TAG, msgType, value);
    return 0;
}

