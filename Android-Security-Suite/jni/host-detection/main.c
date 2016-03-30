#include "detect.h"

//Global Variables
char *target_ip;

int main(int argc, char **argv) {
    uint8_t *src_mac, *dst_mac, *data, *send_ether_frame, *recv_ether_frame, *send_tcp_ether_frame, *recv_tcp_ether_frame;
    struct ip send_iphdr, *recv_iphdr;
    struct icmp send_icmphdr, *recv_icmphdr;
    struct addrinfo hints, *res;
    struct sockaddr_in *ipv4;
    struct sockaddr_ll device;
    struct ifreq ifr;
    struct sockaddr from;
    socklen_t fromlen;
    double dt;
    void *tmp;
    int c, i, status, datalen, frame_length, sendsd, recvsd, bytes, *ip_flags, trycount, done, rc;
    char *interface, *src_ip, *rec_ip, *rec_mac, *dst_ip, *temp;
    pthread_t recv_thread, tcp_thread;
    FILE *fp;
    tcp_frame_struct tcp_frame;

    fp = fopen(FILE_LOC, "w");
    fp_log = fopen(LOG_FILE, "w");


    src_mac = allocate_ustrmem(ETHER_ADDR_LEN);
    dst_mac = allocate_ustrmem(ETHER_ADDR_LEN);
    send_ether_frame = allocate_ustrmem(IP_MAXPACKET);
    send_tcp_ether_frame = allocate_ustrmem(IP_MAXPACKET);
    data = allocate_ustrmem(IP_MAXPACKET);
    interface = allocate_strmem(40);
    src_ip = allocate_strmem(INET_ADDRSTRLEN);
    temp = allocate_strmem(INET_ADDRSTRLEN);
    dst_ip = allocate_strmem(INET_ADDRSTRLEN);
    target_ip = allocate_strmem(INET_ADDRSTRLEN);
    ip_flags = allocate_intmem(4);

    sendsd = create_raw_socket(ETH_P_ALL);

    if (argc < 2) {
        fprintf(stderr, "1. Too Few Arguments\n");
        fprintf(stderr, "Option -%c requires an argument.\n", optopt);
        fprintf(stderr, "[USAGE] => %s -i \"[wlan0 or etho0]\" \n", argv[0]);
        return 1;
    } else {
        while ((c = getopt(argc, argv, "i:")) != -1) {
            switch (c) {
                case 'i':
                    interface = optarg;
                    break;
                case '?':
                    if (optopt == 'i') {
                        fprintf(stderr, "Option -%c requires an argument.\n", optopt);
                        fprintf(stderr, "[USAGE] => %s -i \"[wlan0 or etho0]\" \n", argv[0]);
                    } else if (isprint(optopt)) {
                        fprintf(stderr, "Unknown option `-%c'.\n", optopt);
                    } else {
                        fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
                    }
                    return 1;
            }
        }
    }

    fprintf(fp_log, "%s", "Executing Scan.....\n");


    memcpy(src_mac, get_mac_addr(sendsd, interface), ETHER_ADDR_LEN);

    // Find interface index from interface name and store index in
    // struct sockaddr_ll device, which will be used as an argument of sendto().
    memset(&device, 0, sizeof (device));
    if ((device.sll_ifindex = if_nametoindex(interface)) == 0) {
        perror("2. if_nametoindex() failed to obtain interface index \n");
        exit(EXIT_FAILURE);
    }
    fprintf(stderr, "3. Index for interface %s is %i\n", interface, device.sll_ifindex);

    // Fill out hints for getaddrinfo().
    memset(&hints, 0, sizeof (struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = hints.ai_flags | AI_CANONNAME;

    // Fill out sockaddr_ll.
    device.sll_family = AF_PACKET;
    memcpy(device.sll_addr, src_mac, 6);
    device.sll_halen = 6;

    // ICMP data
    datalen = 4;
    data[0] = 'T';
    data[1] = 'e';
    data[2] = 's';
    data[3] = 't';

    src_ip = get_ip_addr(sendsd, interface);
    fprintf(fp_log, "SRC IP [%s]\n", src_ip);

    // tcp_frame.datalen = datalen;
    // tcp_frame.data = data;
    // tcp_frame.src_mac = src_mac;
    // tcp_frame.src_ip = src_ip;
    // tcp_frame.sendsd = sendsd;
    // tcp_frame.device = device;

    rc = pthread_create(&recv_thread, NULL, capture_packets, (void*) 0);
    if (rc) {
        submit_log_i("3.1 ERROR; Return code from PTHREAD_CREATE() is %d\n", rc);
        exit(EXIT_FAILURE);
    }

    // GET TARGET LOOP STARTS HERE
    for (;;) {
        strcpy(temp, src_ip);
        strcpy(target_ip, get_target_ip(temp)); // Destination IPv4 address
        fprintf(fp_log, "TARGET IP [%s]\n", target_ip);

        // Resolve target using getaddrinfo().
        if ((status = getaddrinfo(target_ip, NULL, &hints, &res)) != 0) {
            fprintf(stderr, "4. getaddrinfo() failed: %s\n", gai_strerror(status));
            exit(EXIT_FAILURE);
        }
        ipv4 = (struct sockaddr_in *) res->ai_addr;
        tmp = &(ipv4->sin_addr);
        if (inet_ntop(AF_INET, tmp, dst_ip, INET_ADDRSTRLEN) == NULL) {
            status = errno;
            fprintf(stderr, "5. inet_ntop() failed. Error message: %s\n", strerror(status));
            exit(EXIT_FAILURE);
        }
        freeaddrinfo(res);

        // TCP THREAD
        // tcp_frame.dst_ip = dst_ip;
        // rc = pthread_create(&tcp_thread, NULL, start_tcp_scan, &tcp_frame);
        // if(rc) {
        // 	submit_log_i("3.2 ERROR; Return code from PTHREAD_CREATE() is %d\n", rc);
        // 	exit(EXIT_FAILURE);
        // }


        // send_iphdr = build_ip_hdr(datalen, src_ip, dst_ip);
        // send_icmphdr = build_icmp_hdr(data, datalen);

        // // Fill out ethernet frame header.

        // // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + ICMP header + ICMP data)
        // frame_length = ETHER_HDRLEN + IP4_HDRLEN + ICMP_HDRLEN + datalen;

        // send_ether_frame = build_ether_frame(frame_length, src_mac, send_iphdr, send_icmphdr, data, datalen);

        // // Submit request for a raw socket descriptor to receive packets.
        // if ((recvsd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
        // 	perror ("socket() failed to obtain a receive socket descriptor ");
        // 	exit (EXIT_FAILURE);
        // }

        // // Set maximum number of tries to ping remote host before giving up.
        // trycount = 0;

        // // Cast recv_iphdr as pointer to IPv4 header within received ethernet frame.
        // recv_iphdr = (struct ip *) (recv_ether_frame + ETHER_HDRLEN);

        // // Case recv_icmphdr as pointer to ICMP header within received ethernet frame.
        // recv_icmphdr = (struct icmp *) (recv_ether_frame + ETHER_HDRLEN + IP4_HDRLEN);


        // Set maximum number of tries to ping remote host before giving up.
        trycount = 0;
        done = 0;
        SEQ_NUM = 1;

        // SEND LOOP STARTS HERE
        for (;;) {

            trycount++;

            send_iphdr = build_ip_hdr(datalen, src_ip, dst_ip, ICMP_PKT);
            send_icmphdr = build_icmp_hdr(data, datalen);

            // Fill out ethernet frame header.

            // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + ICMP header + ICMP data)
            frame_length = ETHER_HDRLEN + IP4_HDRLEN + ICMP_HDRLEN + datalen;

            send_ether_frame = build_ether_frame(frame_length, src_mac, send_iphdr, send_icmphdr, data, datalen);
            build_tcp_frame(send_tcp_ether_frame, src_mac, src_ip, dst_ip, data, datalen);

            // Send ethernet frame to socket.
            if ((bytes = sendto(sendsd, send_ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
                perror("sendto() failed ");
                exit(EXIT_FAILURE);
            }

            if ((bytes = sendto(sendsd, send_tcp_ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
                perror("sendto() failed ");
                exit(EXIT_FAILURE);
            }

            //=======================================================================================================

            // We ran out of tries, so let's give up.
            if (trycount == TRY_LIMIT) {
                break; // Break out of SEND Loop
            }

            usleep(50000);
        }

        if (TARGET_IP == FINAL_TARGET_IP) {
            break; //break the target_ip loop
        }
    }

    pthread_join(tcp_thread, NULL);

    fprintf(fp_log, "%s", "complete\n");

    fclose(fp);
    fclose(fp_log);

    return 0;
}

// captures responses from the devices

void *capture_packets(void *arg) {
    int recvsd, status, bytes;
    struct ip *recv_iphdr;
    struct icmp *recv_icmphdr;
    struct ether_header *recv_etherhdr;
    uint8_t *recv_ether_frame;
    struct timeval wait;
    struct sockaddr from;
    socklen_t fromlen;
    char *rec_ip, *rec_mac;
    FILE *fp;


    recv_ether_frame = allocate_ustrmem(IP_MAXPACKET);
    rec_ip = allocate_strmem(INET_ADDRSTRLEN);
    rec_mac = allocate_strmem(MAC_ADDR_STRLEN);

    // Submit request for a raw socket descriptor to receive packets.
    if ((recvsd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("socket() failed to obtain a receive socket descriptor ");
        exit(EXIT_FAILURE);
    }

    recv_etherhdr = (struct ether_header *) (recv_ether_frame);

    // Cast recv_iphdr as pointer to IPv4 header within received ethernet frame.
    recv_iphdr = (struct ip *) (recv_ether_frame + ETHER_HDRLEN);

    // Case recv_icmphdr as pointer to ICMP header within received ethernet frame.
    recv_icmphdr = (struct icmp *) (recv_ether_frame + ETHER_HDRLEN + IP4_HDRLEN);

    // Set time for the socket to timeout and give up waiting for a reply.
    //wait.tv_sec  = TIMEOUT;  
    //wait.tv_usec = 0;
    //setsockopt (recvsd, SOL_SOCKET, SO_RCVTIMEO, (char *) &wait, sizeof (struct timeval));

    for (;;) {
        memset(recv_ether_frame, 0, IP_MAXPACKET * sizeof (uint8_t));
        memset(&from, 0, sizeof (from));
        fromlen = sizeof (from);

        if ((bytes = recvfrom(recvsd, recv_ether_frame, IP_MAXPACKET, 0, (struct sockaddr *) &from, &fromlen)) < 0) {

            status = errno;

            if (status == EINTR) { // EINTR = 4
                continue; // Something weird happened, but let's keep listening.
            } else {
                submit_log("capture_packets() => %s", "recvfrom() failed ");
                exit(EXIT_FAILURE);
            }
        } // End of error handling conditionals.

        // Check for an IP ethernet frame, carrying ICMP echo reply. If not, ignore and keep listening.
        if ((((recv_ether_frame[12] << 8) + recv_ether_frame[13]) == ETH_P_IP) &&
                (recv_iphdr->ip_p == IPPROTO_ICMP) && (recv_icmphdr->icmp_type == ICMP_ECHOREPLY) && (recv_icmphdr->icmp_code == 0)) {

            // Extract source IP address from received ethernet frame
            if (inet_ntop(AF_INET, &(recv_iphdr->ip_src.s_addr), rec_ip, INET_ADDRSTRLEN) == NULL) {
                status = errno;
                fprintf(stderr, "inet_ntop() failed.\nError message: %s", strerror(status));
                exit(EXIT_FAILURE);
            }

            strcpy(rec_mac, (char *) recv_etherhdr->ether_shost);
            sprintf(rec_mac, "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", recv_etherhdr->ether_shost[0], recv_etherhdr->ether_shost[1], recv_etherhdr->ether_shost[2], recv_etherhdr->ether_shost[3], recv_etherhdr->ether_shost[4], recv_etherhdr->ether_shost[5]);

            // Report source IPv4 address and time for reply.
            //fprintf (stdout, "IP = %s (%i bytes received)\n", rec_ip, bytes);
            //fprintf (stdout, "IP = %s, MAC = %s (%i bytes received)\n", rec_ip, rec_mac, bytes);
            write_to_file(rec_ip, rec_mac);
            //done = 1;
        } // End if IP ethernet frame carrying ICMP_ECHOREPLY
    }
}

void *start_tcp_scan(void *arg) {
    uint8_t *send_ether_frame, *recv_ether_frame;
    int sendsd, frame_length, bytes;
    tcp_frame_struct *tcp_frame = (tcp_frame_struct *) arg;
    struct sockaddr_ll device;

    sendsd = tcp_frame->sendsd;
    device = tcp_frame->device;

    fprintf(fp_log, "TCP PACKET: %s\n", tcp_frame->dst_ip);
    send_ether_frame = allocate_ustrmem(IP_MAXPACKET);

    build_tcp_frame(send_ether_frame, tcp_frame->src_mac, tcp_frame->src_ip, tcp_frame->dst_ip, tcp_frame->data, tcp_frame->datalen);

    frame_length = ETHER_HDRLEN + IP4_HDRLEN + TCP_HDRLEN + tcp_frame->datalen;

    if ((bytes = sendto(sendsd, send_ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
        perror("sendto() failed");
        exit(EXIT_FAILURE);
    }
}

// write IP:MAC to the file

int write_to_file(char *recv_ip, char *recv_mac) {
    FILE *fp_read, *fp_write;
    char *token;
    int device_exists = 0;

    // read the file to see if the entry exists
    fp_read = fopen(FILE_LOC, "r");
    if (fp_read != NULL) {
        char line[128];
        while (fgets(line, sizeof (line), fp_read) != NULL) {
            token = strtok(line, "-");
            if (strcmp(recv_ip, token) == 0) {
                device_exists = 1; // device already exists in the file
                break;
            }
        }

        fclose(fp_read); // Close the file for Reading
    }

    // device doesn't exist in the file
    if (device_exists == 0) {
        // print an output
        fprintf(stdout, "IP = %s, MAC = %s\n", recv_ip, recv_mac);

        // write to the file
        fp_write = fopen(FILE_LOC, "a");
        fprintf(fp_write, "%s-%s\n", recv_ip, recv_mac);
        fclose(fp_write);
    }



    return 0;
}

// Frame

uint8_t* build_ether_frame(int frame_length, uint8_t *src_mac, struct ip send_iphdr, struct icmp send_icmphdr, uint8_t *data, int datalen) {
    uint8_t *send_ether_frame, *dst_mac;
    send_ether_frame = allocate_ustrmem(IP_MAXPACKET);
    dst_mac = allocate_ustrmem(ETHER_ADDR_LEN);

    // Set destination MAC address: you need to fill these out
    dst_mac[0] = 0xFF;
    dst_mac[1] = 0xFF;
    dst_mac[2] = 0xFF;
    dst_mac[3] = 0xFF;
    dst_mac[4] = 0xFF;
    dst_mac[5] = 0xFF;

    // Destination and Source MAC addresses
    memcpy(send_ether_frame, dst_mac, 6);
    memcpy(send_ether_frame + 6, src_mac, 6);

    // Next is ethernet type code (ETH_P_IP for IPv4).
    // http://www.iana.org/assignments/ethernet-numbers
    send_ether_frame[12] = ETH_P_IP / 256;
    send_ether_frame[13] = ETH_P_IP % 256;

    // Next is ethernet frame data (IPv4 header + ICMP header + ICMP data).

    // IPv4 header
    memcpy(send_ether_frame + ETHER_HDRLEN, &send_iphdr, IP4_HDRLEN);

    // ICMP header
    memcpy(send_ether_frame + ETHER_HDRLEN + IP4_HDRLEN, &send_icmphdr, ICMP_HDRLEN);

    // ICMP data
    memcpy(send_ether_frame + ETHER_HDRLEN + IP4_HDRLEN + ICMP_HDRLEN, data, datalen);

    return send_ether_frame;
}

// IPv4 header (0 = icmp, 6 = tcp)

struct ip build_ip_hdr(int datalen, char *src_ip, char *dst_ip, int type) {
    struct ip send_iphdr;
    int *ip_flags, status, id;
    time_t t;

    /* Intializes random number generator */
    srand((unsigned) time(&t));

    ip_flags = allocate_intmem(4);

    // IPv4 header length (4 bits): Number of 32-bit words in header = 5
    send_iphdr.ip_hl = IP4_HDRLEN / sizeof (uint32_t);

    // Internet Protocol version (4 bits): IPv4
    send_iphdr.ip_v = 4;

    // Type of service (8 bits)
    send_iphdr.ip_tos = 0;

    // Total length of datagram (16 bits): IP header + ICMP header + ICMP data
    send_iphdr.ip_len = htons(IP4_HDRLEN + ICMP_HDRLEN + datalen);

    // ID sequence number (16 bits): unused, since single datagram
    id = rand() % 9999 + 1;
    send_iphdr.ip_id = htons(id);

    // Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram

    // Zero (1 bit)
    ip_flags[0] = 0;

    // Do not fragment flag (1 bit)
    ip_flags[1] = 1;

    // More fragments following flag (1 bit)
    ip_flags[2] = 0;

    // Fragmentation offset (13 bits)
    ip_flags[3] = 0;

    send_iphdr.ip_off = htons((ip_flags[0] << 15)
            + (ip_flags[1] << 14)
            + (ip_flags[2] << 13)
            + ip_flags[3]);

    // Time-to-Live (8 bits): default to maximum value
    send_iphdr.ip_ttl = 64;

    if (type == ICMP_PKT) {
        // Transport layer protocol (8 bits): 1 for ICMP
        send_iphdr.ip_p = IPPROTO_ICMP;
    } else if (type == TCP_PKT) {
        send_iphdr.ip_p = IPPROTO_TCP;
    }

    // Source IPv4 address (32 bits)
    if ((status = inet_pton(AF_INET, src_ip, &(send_iphdr.ip_src))) != 1) {
        fprintf(stderr, "6. inet_pton() failed. Status: %d > Error message: %s\n", status, strerror(status));
        exit(EXIT_FAILURE);
    }

    // Destination IPv4 address (32 bits)
    if ((status = inet_pton(AF_INET, dst_ip, &(send_iphdr.ip_dst))) != 1) {
        fprintf(stderr, "7. inet_pton() failed. Status: %d > Error message: %s\n", status, strerror(status));
        exit(EXIT_FAILURE);
    }

    // IPv4 header checksum (16 bits): set to 0 when calculating checksum
    send_iphdr.ip_sum = 0;
    send_iphdr.ip_sum = ipv4_checksum((uint16_t *) & send_iphdr, IP4_HDRLEN);

    return send_iphdr;
}

// ICMP header

struct icmp build_icmp_hdr(uint8_t *data, int datalen) {
    struct icmp send_icmphdr;

    // Message Type (8 bits): echo request
    send_icmphdr.icmp_type = ICMP_ECHO;

    // Message Code (8 bits): echo request
    send_icmphdr.icmp_code = 0;

    // Identifier (16 bits): usually pid of sending process - pick a number
    send_icmphdr.icmp_id = htons(1000);

    // Sequence Number (16 bits): starts at 0
    send_icmphdr.icmp_seq = htons(SEQ_NUM);
    SEQ_NUM++;

    // ICMP header checksum (16 bits): set to 0 when calculating checksum
    send_icmphdr.icmp_cksum = icmp4_checksum(send_icmphdr, data, datalen);

    return send_icmphdr;
}

// TCP Header

int build_tcp_frame(uint8_t *send_ether_frame, uint8_t *src_mac, char *src_ip, char *dst_ip, uint8_t *data, int datalen) {
    int i, status, *tcp_flags;
    uint8_t *dst_mac;
    struct ip iphdr;
    struct tcphdr tcphdr;

    /* From synhose.c by knight */
    struct pseudo_header {
        unsigned int source_address;
        unsigned int dest_address;
        unsigned char placeholder;
        unsigned char protocol;
        unsigned short tcp_length;
        struct tcphdr tcp;
    } pseudo_header;

    // Allocate memory for various arrays.
    dst_mac = allocate_ustrmem(ETHER_ADDR_LEN);
    tcp_flags = allocate_intmem(8);

    // Set destination MAC address: you need to fill these out
    dst_mac[0] = 0xFF;
    dst_mac[1] = 0xFF;
    dst_mac[2] = 0xFF;
    dst_mac[3] = 0xFF;
    dst_mac[4] = 0xFF;
    dst_mac[5] = 0xFF;

    iphdr = build_ip_hdr(datalen, src_ip, dst_ip, TCP_PKT);

    // TCP header

    //TCP Header
    tcphdr.source = htons(42591);
    tcphdr.dest = htons(80);
    tcphdr.seq = htonl(1105024978);
    tcphdr.ack_seq = 0;
    tcphdr.res1 = 0;
    tcphdr.doff = sizeof (struct tcphdr) / 4; //Size of tcp header
    tcphdr.fin = 0;
    tcphdr.syn = 1;
    tcphdr.rst = 0;
    tcphdr.psh = 0;
    tcphdr.ack = 0;
    tcphdr.urg = 0;
    tcphdr.window = htons(14600); // maximum allowed window size
    tcphdr.check = 0; //if you set a checksum to zero, your kernel's IP stack should fill in the correct checksum during transmission
    tcphdr.urg_ptr = 0;

    // TCP checksum (16 bits)
    //tcphdr.check = tcp4_checksum (iphdr, tcphdr, data, datalen);

    // Fill out ethernet frame header.

    // Destination and Source MAC addresses
    memcpy(send_ether_frame, dst_mac, 6 * sizeof (uint8_t));
    memcpy(send_ether_frame + 6, src_mac, 6 * sizeof (uint8_t));

    // Next is ethernet type code (ETH_P_IP for IPv4).
    // http://www.iana.org/assignments/ethernet-numbers
    send_ether_frame[12] = ETH_P_IP / 256;
    send_ether_frame[13] = ETH_P_IP % 256;

    // Next is ethernet frame data (IPv4 header + TCP header).

    // IPv4 header
    memcpy(send_ether_frame + ETHER_HDRLEN, &iphdr, IP4_HDRLEN * sizeof (uint8_t));

    // TCP header
    memcpy(send_ether_frame + ETHER_HDRLEN + IP4_HDRLEN, &tcphdr, TCP_HDRLEN * sizeof (uint8_t));

    // TCP data
    memcpy(send_ether_frame + ETHER_HDRLEN + IP4_HDRLEN + TCP_HDRLEN, data, datalen * sizeof (uint8_t));

    // Free allocated memory.
    free(tcp_flags);

    return EXIT_SUCCESS;
}

uint16_t ipv4_checksum(uint16_t *addr, int len) {
    int count = len;
    register uint32_t sum = 0;
    uint16_t answer = 0;

    // Sum up 2-byte values until none or only one byte left.
    while (count > 1) {
        sum += *(addr++);
        count -= 2;
    }

    // Add left-over byte, if any.
    if (count > 0) {
        sum += *(uint8_t *) addr;
    }

    // Fold 32-bit sum into 16 bits; we lose information by doing this,
    // increasing the chances of a collision.
    // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // Checksum is one's compliment of sum.
    answer = ~sum;

    return (answer);
}

// Build IPv4 ICMP pseudo-header and call checksum function.

uint16_t icmp4_checksum(struct icmp icmphdr, uint8_t *payload, int payloadlen) {
    char buf[IP_MAXPACKET];
    char *ptr;
    int chksumlen = 0;
    int i;

    ptr = &buf[0]; // ptr points to beginning of buffer buf

    // Copy Message Type to buf (8 bits)
    memcpy(ptr, &icmphdr.icmp_type, sizeof (icmphdr.icmp_type));
    ptr += sizeof (icmphdr.icmp_type);
    chksumlen += sizeof (icmphdr.icmp_type);

    // Copy Message Code to buf (8 bits)
    memcpy(ptr, &icmphdr.icmp_code, sizeof (icmphdr.icmp_code));
    ptr += sizeof (icmphdr.icmp_code);
    chksumlen += sizeof (icmphdr.icmp_code);

    // Copy ICMP checksum to buf (16 bits)
    // Zero, since we don't know it yet
    *ptr = 0;
    ptr++;
    *ptr = 0;
    ptr++;
    chksumlen += 2;

    // Copy Identifier to buf (16 bits)
    memcpy(ptr, &icmphdr.icmp_id, sizeof (icmphdr.icmp_id));
    ptr += sizeof (icmphdr.icmp_id);
    chksumlen += sizeof (icmphdr.icmp_id);

    // Copy Sequence Number to buf (16 bits)
    memcpy(ptr, &icmphdr.icmp_seq, sizeof (icmphdr.icmp_seq));
    ptr += sizeof (icmphdr.icmp_seq);
    chksumlen += sizeof (icmphdr.icmp_seq);

    // Copy payload to buf
    memcpy(ptr, payload, payloadlen);
    ptr += payloadlen;
    chksumlen += payloadlen;

    // Pad to the next 16-bit boundary
    for (i = 0; i < payloadlen % 2; i++, ptr++) {
        *ptr = 0;
        ptr++;
        chksumlen++;
    }

    return ipv4_checksum((uint16_t *) buf, chksumlen);
}

char* get_target_ip(char *src_ip) {
    char *target_ip_adr;
    char *ip;
    int i = 0;
    char *array[4];

    ip = strtok(src_ip, ".");
    while (ip != NULL) {
        array[i] = ip;
        i++;
        ip = strtok(NULL, ".");
    }

    target_ip_adr = allocate_strmem(INET_ADDRSTRLEN);

    sprintf(target_ip_adr, "%s.%s.%s.%d", array[0], array[1], array[2], TARGET_IP);
    TARGET_IP++;

    submit_log("8. target_ip selected [%s] \n", target_ip_adr);

    return target_ip_adr;
}

int create_raw_socket(int socket_type) {
    int raw;

    if ((raw = socket(PF_PACKET, SOCK_RAW, htons(socket_type))) < 0) {
        submit_log("9. [%s]\n", "Socket(): failed to get socket descriptor for using ioctl()");
        exit(EXIT_FAILURE);
    }

    return raw;
}

uint8_t* get_mac_addr(int socket, char *interface) {
    uint8_t *src_mac;
    struct ifreq ifr;

    memset(&ifr, 0, sizeof (ifr));
    bzero(&ifr, sizeof (ifr));

    src_mac = allocate_ustrmem(ETHER_ADDR_LEN);

    strncpy((char *) ifr.ifr_name, interface, IFNAMSIZ);

    if ((ioctl(socket, SIOCGIFHWADDR, &ifr)) == -1) {
        submit_log("10. create_raw_socket(): [%s]\n", "Error getting HW ADDR");
        exit(EXIT_FAILURE);
    }
    memcpy(src_mac, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN * sizeof (uint8_t));

    print_mac_addr(src_mac);

    return src_mac;
}

void print_mac_addr(uint8_t *mac) {
    int i;
    fprintf(stderr, "MAC ADDR: ");
    for (i = 0; i < 5; i++) {
        fprintf(stderr, "%02x:", mac[i]);
    }
    fprintf(stderr, "%02x\n", mac[5]);
}

char* get_ip_addr(int socket, char *interface) {
    char *src_ip;
    struct ifreq ifr;

    memset(&ifr, 0, sizeof (ifr));
    bzero(&ifr, sizeof (ifr));

    src_ip = allocate_strmem(INET_ADDRSTRLEN);

    strncpy((char *) ifr.ifr_name, interface, IFNAMSIZ);

    if ((ioctl(socket, SIOCGIFADDR, &ifr)) == -1) {
        submit_log("11. get_ip_addr(): [%s]\n", "Error getting IP ADDR");
        exit(EXIT_FAILURE);
    }

    strcpy(src_ip, inet_ntoa(((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr));

    submit_log("12. IP ADDR: %s\n", src_ip);
    return src_ip;
}

// Allocate memory for an array of unsigned chars.

uint8_t * allocate_ustrmem(int len) {
    void *tmp;

    if (len <= 0) {
        fprintf(stderr, "13. ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
        exit(EXIT_FAILURE);
    }

    tmp = (uint8_t *) malloc(len * sizeof (uint8_t));
    if (tmp != NULL) {
        memset(tmp, 0, len * sizeof (uint8_t));
        return (tmp);
    } else {
        fprintf(stderr, "14. ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
        exit(EXIT_FAILURE);
    }
}

// Allocate memory for an array of chars.

char * allocate_strmem(int len) {
    void *tmp;

    if (len <= 0) {
        fprintf(stderr, "15. ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
        exit(EXIT_FAILURE);
    }

    tmp = (char *) malloc(len * sizeof (char));
    if (tmp != NULL) {
        memset(tmp, 0, len * sizeof (char));
        return (tmp);
    } else {
        fprintf(stderr, "16. ERROR: Cannot allocate memory for array allocate_strmem().\n");
        exit(EXIT_FAILURE);
    }
}

// Allocate memory for an array of ints.

int* allocate_intmem(int len) {
    void *tmp;

    if (len <= 0) {
        fprintf(stderr, "17. ERROR: Cannot allocate memory because len = %i in allocate_intmem().\n", len);
        exit(EXIT_FAILURE);
    }

    tmp = (int *) malloc(len * sizeof (int));
    if (tmp != NULL) {
        memset(tmp, 0, len * sizeof (int));
        return (tmp);
    } else {
        fprintf(stderr, "18. ERROR: Cannot allocate memory for array allocate_intmem().\n");
        exit(EXIT_FAILURE);
    }
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