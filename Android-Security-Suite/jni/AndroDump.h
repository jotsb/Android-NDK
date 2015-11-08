/* Header for class com_example_android_ndk_example_NDKMethods */
#undef __cplusplus
#undef _GNU_SOURCE
#include <jni.h>
#include <android/log.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <ctype.h>

#include <pthread.h>

/*
#include <netinet/tcp.h>
#include <sys/types.h>
#include <netinet/in.h>
*/

#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/socket.h>


#include <pcap.h>

#ifndef NULL
#define NULL   ((void *) 0)
#endif


#ifndef _Included_AndroDump
#define _Included_AndroDump
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     com_example_hello_c_world_NDKMethods
 * Method:    set_msg
 * Signature: (Ljava/lang/String;)Ljava/lang/String;
 */
//JNIEXPORT jstring JNICALL ava_com_example_android_1ndk_1example_NDKMethods_set_1msg
//  (JNIEnv *, jclass, jstring);

int submit_log(char *msgType, char *string);

#ifdef __cplusplus
}
#endif
#endif
