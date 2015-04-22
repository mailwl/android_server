
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := android_server
LOCAL_CXXFLAGS    :=  -I/idasdk66/include -D__ANDROID__=1 -D__LINUX__=1 -D__ARM__=1
LOCAL_SRC_FILES :=	ida.cpp android.cpp\
					server.cpp debmod.cpp arm_debmod.cpp linuxbase_debmod.cpp linux_debmod.cpp rpc_engine.cpp  \
					rpc_hlp.cpp rpc_server.cpp tcpip.cpp util.cpp linux_wait.cpp symelf.cpp
LOCAL_LDLIBS    := -landroid
LOCAL_STATIC_LIBRARIES := pthread

include $(BUILD_EXECUTABLE)

