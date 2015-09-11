LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := Android-NDK-Example
LOCAL_SRC_FILES := Android-NDK-Example.cpp

include $(BUILD_SHARED_LIBRARY)
