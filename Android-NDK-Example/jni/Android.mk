LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := com_example_android_ndk_example_NDKMethods
LOCAL_SRC_FILES := com_example_android_ndk_example_NDKMethods.c

LOCAL_C_INCLUDES := $(LOCAL_PATH)/libpcap
LOCAL_STATIC_LIBRARIES := libpcap

#LOCAL_CFLAGS := -DLIBPCAP_VERSION=0x097 -lpcap

LOCAL_LDLIBS := -ldl -llog

include $(BUILD_SHARED_LIBRARY)
#include $(BUILD_EXECUTABLE)

include $(LOCAL_PATH)/libpcap/Android.mk
