all:
	$(ANDROID_NDK)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang --std=c99 -Iinclude src/*.c -o csoloader -Wno-int-conversion -g -O0 -D_FORTIFY_SOURCE=2 -fstack-protector-strong 
	adb push csoloader /data/local/tmp/csoloader

linux:
	$(CC) --std=c99 -D_GNU_SOURCE -Iinclude src/*.c -o csoloader -Wno-int-conversion -g -O0 -lunwind
