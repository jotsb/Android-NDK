LOCAL_PATH := $(call my-dir)
MY_LOCAL_PATH := $(LOCAL_PATH)

include $(CLEAR_VARS)

include $(MY_LOCAL_PATH)/androdump/Android.mk
include $(MY_LOCAL_PATH)/arpspoof/Android.mk
include $(MY_LOCAL_PATH)/host-detection/Android.mk
include $(MY_LOCAL_PATH)/dns-spoofing/Android.mk
include $(MY_LOCAL_PATH)/libpcap/Android.mk