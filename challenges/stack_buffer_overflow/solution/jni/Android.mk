LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := stack_buffer_overflow_exploit
LOCAL_SRC_FILES := stack_buffer_overflow_exploit.c

LOCAL_LDLIBS := -static

include $(BUILD_EXECUTABLE)

