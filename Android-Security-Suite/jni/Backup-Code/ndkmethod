/* Header for class com_example_hello_c_world_NDKMethods */
#include "com_example_hello_c_world_NDKMethods.h"

#define DEBUG_TAG "Sample_LIBPCAP_DEBUGGING"

/*
 * Class:     com_example_hello_c_world_NDKMethods
 * Method:    set_msg
 * Signature: (Ljava/lang/String;)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_example_hello_1c_1world_NDKMethods_set_1msg(
		JNIEnv *env, jclass class, jstring javaString) {

	const char *str = (*env)->GetStringUTFChars(env, javaString, NULL);

	char *dev; /* name of the device to use */
	char *net; /* dot notation of the network address */
	char *mask;/* dot notation of the network mask    */
	int ret; /* return code */
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 netp; /* ip          */
	bpf_u_int32 maskp;/* subnet mask */
	struct in_addr addr;

	/* ask pcap to find a valid device for use to sniff on */
	dev = pcap_lookupdev(errbuf);

	/* error checking */
	if (dev == NULL) {
		printf("%s\n", errbuf);
		__android_log_print(ANDROID_LOG_DEBUG, DEBUG_TAG, "errbuf [%s]", errbuf);
		exit(1);
	}

	/* print out device name */
	printf("DEV: %s\n", dev);
	__android_log_print(ANDROID_LOG_DEBUG, DEBUG_TAG, "Device status: [%s]", dev);

	/* ask pcap for the network address and mask of the device */
	ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);

	if (ret == -1) {
		printf("%s\n", errbuf);
		__android_log_print(ANDROID_LOG_DEBUG, DEBUG_TAG, "errbuf [%s]", errbuf);
		exit(1);
	}

	/* get the network address in a human readable form */
	addr.s_addr = netp;
	net = inet_ntoa(addr);

	if (net == NULL)/* thanks Scott :-P */
	{
		perror("inet_ntoa");
		exit(1);
	}

	printf("NET: %s\n", net);
	__android_log_print(ANDROID_LOG_DEBUG, DEBUG_TAG, "Net status: [%s]", net);

	/* do the same as above for the device's mask */
	addr.s_addr = maskp;
	mask = inet_ntoa(addr);

	if (mask == NULL) {
		perror("inet_ntoa");
		exit(1);
	}

	printf("MASK: %s\n", mask);
	__android_log_print(ANDROID_LOG_DEBUG, DEBUG_TAG, "MASK: [%s]", mask);


	return (*env)->NewStringUTF(env, str);
}
