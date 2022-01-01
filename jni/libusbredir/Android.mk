#libusbredir Android mk file to build shared library using NDK

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := usbredir
LOCAL_C_INCLUDES := $(LOCAL_PATH)/usbredirparser \
		    $(LOCAL_PATH)/usbredirfilter \
		    $(LOCAL_PATH)/usbredirhost \
		    $(LOCAL_PATH)/usbredirserver \
		    $(LOCAL_PATH)/include \
		    $(LOCAL_PATH)/../libusb/libusb
LOCAL_SRC_FILES := usbredirparser/usbredirfilter.c \
		   usbredirparser/usbredirparser.c \
		   usbredirparser/strtok_r.c \
		   usbredirhost/usbredirhost.c \
		   usbredirserver/usbredirserver.c
LOCAL_SHARED_LIBRARIES := libusb1.0
include $(BUILD_SHARED_LIBRARY)
