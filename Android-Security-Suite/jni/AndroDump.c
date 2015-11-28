/* Header for class com_example_android_ndk_example_NDKMethods*/
#include "AndroDump.h"

#define DEBUG_TAG "\n[ANDROID_SECURITY_SUITE] ===> LIBPCAP_DEBUGGING ======> "

int main(int argc, char **argv) {

	// Device name, network address, network mask
	char *dev, *net, *mask;
	char errbuf[PCAP_ERRBUF_SIZE];
	int ret; // return code
	bpf_u_int32 netp, maskp; // ip, subnet mask
	struct in_addr addr;
	pcap_t* nic_descr;
	u_char* args = NULL;

	//const char *str = (*env)->GetStringUTFChars(env, javaString, NULL);

	// find the first NIC that is up and sniff packets from it
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		submit_log("errbuf: [%s]\n", errbuf);
		exit(1);
	}
	submit_log("Device: [%s]\n", dev);

	// Use pcap to get the IP address and subnet mask of the device
	ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
	if (ret == -1) {
		submit_log("errbuf: [%s]\n", errbuf);
		exit(1);
	}

	// open device for reading
	nic_descr = pcap_open_live(dev, BUFSIZ, 1, -1, errbuf);
	if (nic_descr = NULL) {
		submit_log("pcap_open_live(): %s \n", errbuf);
		exit(1);
	}

	pcap_loop(nic_descr, atoi(argv[1]), pkt_callback, args);

	/* get the network address in a human readable form
	 addr.s_addr = netp;
	 net = inet_ntoa(addr);
	 if (net == NULL) {
	 submit_log("errbuf: [%s]\n", "inet_ntoa failed");
	 exit(1);
	 }
	 submit_log("Net status: [%s]\n", net);

	 addr.s_addr = maskp;
	 mask = inet_ntoa(addr);
	 if (mask == NULL) {
	 submit_log("errbuf: [%s]\n", "inet_ntoa failed");
	 exit(1);
	 }
	 submit_log("MASK: [%s]\n", mask);*/

	return 0;
}

void pkt_callback(u_char *ptr_null, const struct pcap_pkthdr* pkthdr,
		const u_char* packet) {
}

int submit_log(char *msgType, char *string) {
	__android_log_print(ANDROID_LOG_DEBUG, DEBUG_TAG, msgType, string);
	//printf(msgType, string);
	return 0;
}
