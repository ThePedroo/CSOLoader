all:
# This breaks C++ exceptions. Worth researching: -Wl,--no-eh-frame-hdr
	$(ANDROID_NDK)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang++ cpp-shared.cpp -llog -lm -shared -g -O0 -fPIC
	adb push a.out /data/local/tmp/shared.so
	rm a.out

linux:
	$(CC) linux-shared.c -lelf -shared -g -O0

linux_cpp:
	$(CXX) cpp-shared.cpp -shared -g -O0 -fPIC
	mv a.out ../libelf.so