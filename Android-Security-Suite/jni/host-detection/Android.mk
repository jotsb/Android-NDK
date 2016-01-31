LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    		:= host-detect
LOCAL_SRC_FILES 		:= main.c

APP_OPTIM 				:= debug

LOCAL_CFLAGS 			:= -DLIBPCAP_VERSION=0x097 -lpcap
LOCAL_LDLIBS 			:= -ldl -llog

LOCAL_C_INCLUDES 		:= $(LOCAL_PATH)/../libpcap
LOCAL_STATIC_LIBRARIES 	:= libpcap

include $(BUILD_EXECUTABLE)
