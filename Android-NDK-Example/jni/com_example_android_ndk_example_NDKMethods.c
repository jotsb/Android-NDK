/* Header for class com_example_android_ndk_example_NDKMethods*/
#include "com_example_android_ndk_example_NDKMethods.h"

#define DEBUG_TAG "Sample_LIBPCAP_DEBUGGING"

/*
 * Class:     com_example_android_ndk_example_NDKMethods
 * Method:    set_msg
 * Signature: (Ljava/lang/String;)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_example_android_1ndk_1example_NDKMethods_set_1msg(
		JNIEnv *env, jclass class, jstring javaString) {

	char *dev; /* name of the device to use */
	char *net; /* dot notation of the network address */
	char *mask;/* dot notation of the network mask    */
	char errbuf[PCAP_ERRBUF_SIZE];

	int ret; /* return code */

	bpf_u_int32 netp; /* ip          */
	bpf_u_int32 maskp;/* subnet mask */

	struct in_addr addr;

	const char *str = (*env)->GetStringUTFChars(env, javaString, NULL);

	dev = pcap_lookupdev(errbuf);

	if (dev == NULL) {
		__android_log_print(ANDROID_LOG_DEBUG, DEBUG_TAG, "errbuf: [%s]",
				errbuf);
		exit(1);
	}
	__android_log_print(ANDROID_LOG_DEBUG, DEBUG_TAG, "Device: [%s]", dev);

	return (*env)->NewStringUTF(env, str);
}
