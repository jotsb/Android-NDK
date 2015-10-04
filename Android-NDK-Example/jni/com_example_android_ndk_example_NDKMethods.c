/* Header for class com_example_android_ndk_example_NDKMethods*/
#include "com_example_android_ndk_example_NDKMethods.h"

#define DEBUG_TAG "\nLIBPCAP_DEBUGGING =============> "

int main() {

	char *dev; /* name of the device to use */
	char *net; /* dot notation of the network address */
	char *mask;/* dot notation of the network mask    */
	char errbuf[PCAP_ERRBUF_SIZE];

	int ret; /* return code */

	bpf_u_int32 netp; /* ip          */
	bpf_u_int32 maskp;/* subnet mask */

	struct in_addr addr;

	//const char *str = (*env)->GetStringUTFChars(env, javaString, NULL);

	setuid(0);
	setgid(0);

	dev = pcap_lookupdev(errbuf);

	if (dev == NULL) {
		log("errbuf: [%s]", errbuf);
		exit(1);
	}
	log("Device: [%s]", dev);

	ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);

	if (ret == -1) {
		log("errbuf: [%s]", errbuf);
		exit(1);
	}

	/* get the network address in a human readable form */
	addr.s_addr = netp;
	net = inet_ntoa(addr);
	if (net == NULL) {
		log("errbuf: [%s]", "inet_ntoa failed");
		exit(1);
	}
	log("Net status: [%s]", net);

	addr.s_addr = maskp;
	mask = inet_ntoa(addr);
	if (mask == NULL) {
		log("errbuf: [%s]", "inet_ntoa failed");
		exit(1);
	}

	log("MASK: [%s]", mask);

	return 0;
}


int log(char *msgType, char *string) {
	__android_log_print(ANDROID_LOG_DEBUG, DEBUG_TAG, msgType, string);
	return 0;
}
