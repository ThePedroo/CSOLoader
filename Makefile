NDK_PATH ?= $(HOME)/Android/Sdk/ndk/29.0.13113456
API_LEVEL ?= 26
ARCH ?= arm64-v8a

TOOLCHAIN = $(NDK_PATH)/toolchains/llvm/prebuilt/linux-x86_64
SYSROOT = $(TOOLCHAIN)/sysroot
CC = $(TOOLCHAIN)/bin/clang
AR = $(TOOLCHAIN)/bin/llvm-ar

TARGET_arm64-v8a = aarch64-linux-android$(API_LEVEL)
TARGET_armeabi-v7a = armv7a-linux-androideabi$(API_LEVEL)
TARGET_x86 = i686-linux-android$(API_LEVEL)
TARGET_x86_64 = x86_64-linux-android$(API_LEVEL)

CC_ARCH = $(CC) --target=$(TARGET_$(ARCH)) --sysroot=$(SYSROOT)

CFLAGS_BASE = -std=c99 -DANDROID -fPIC -Wno-int-conversion           \
	          -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Iinclude

CFLAGS_debug = $(CFLAGS_BASE) -g -O0 -DCSOLOADER_DEBUG
CFLAGS_release = $(CFLAGS_BASE) -O3 -flto

BUILD_TYPE ?= debug
out ?= build/$(BUILD_TYPE)/$(ARCH)

CFLAGS = $(CFLAGS_$(BUILD_TYPE))
SRCS = src/backtrace-support.c src/carray.c src/csoloader.c \
	   src/elf_util.c src/linker.c src/sleb128.c
OBJS = $(patsubst src/%.c,$(out)/%.o,$(SRCS))
LIB = $(out)/libcsoloader.a

.PHONY: all lib_debug lib_release standalone linux clean

all: $(LIB)

lib_debug:
	$(MAKE) BUILD_TYPE=debug out=build/debug/$(ARCH) all

lib_release:
	$(MAKE) BUILD_TYPE=release out=build/release/$(ARCH) all

standalone:
	$(ANDROID_NDK)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang        \
		--std=c99 -Iinclude src/*.c -o csoloader                                                  \
		-Wno-int-conversion -g -O0 -D_FORTIFY_SOURCE=2 -fstack-protector-strong -DSTANDALONE_TEST
	adb push csoloader /data/local/tmp/csoloader

linux:
	$(CC) --std=c99 -D_GNU_SOURCE -Iinclude src/*.c -o csoloader \
		-Wno-int-conversion -g -O0 -lunwind

$(out)/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC_ARCH) $(CFLAGS) -c $< -o $@

$(LIB): $(OBJS)
	@mkdir -p $(dir $@)
	$(AR) rcs $@ $^

clean:
	rm -rf build
	rm -f csoloader
