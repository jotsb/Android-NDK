// NDK Header Files
#include <jni.h>
#include <android/log.h>

#define DEBUG_TAG "\n[ANDROID_SECURITY_SUITE] ===> LIBPCAP_DEBUGGING ======> "

// Android Logging
int submit_log(char *msgType, char *string);
int submit_log_i(char *msgType, int value);


// Allocate memory
uint8_t *allocate_ustrmem (int len);
char * allocate_strmem (int len);
int* allocate_intmem (int len);