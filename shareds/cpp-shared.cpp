/* Copyright (c) 2025 ThePedroo. All rights reserved.
 *
 * This source code is licensed under the GNU AGPLv3 License found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <link.h>
#include <dlfcn.h>
#include <unwind.h>
#include <execinfo.h>

#include <android/log.h>
#include <sys/prctl.h>

#include <typeinfo>
#include <stdexcept>

/* TODO: Implement dependency dependency test */

extern "C" {
  void test_relocation() {
    printf("Testing relocation functionality...\n");

    __android_log_print(ANDROID_LOG_INFO, "CSOLoader-Test", "This is a pretty insane linker, innit?");

    double value = 0.5;
    double result = cos(value);

    if (result == 0.8775825618903728) {
      printf("Relocation test completed.\n");
    } else {
      printf("----------------- RELOCATION TEST FAILED -----------------\n");
    }
  }

  void test_mte() {
    printf("See MTE functionality...\n");

    if (prctl(PR_SET_TAGGED_ADDR_CTRL, PR_TAGGED_ADDR_ENABLE, 0, 0, 0) == 0) {
      printf("MTE is NOT supported on this device.\n");
    } else {
      /* INFO: won't even run. CSOLoader has no support for such devices. (arm9) */
      printf("MTE is supported on this device.\n");
    }

    printf("MTE test completed.\n");
  }

  #define GUARD_MAGIC 0x12345678
  void test_guard() {
    printf("Testing static initialization guard...\n");

    static int guard_value = []() {
      printf("Static initialization guard executed.\n");

      return GUARD_MAGIC;
    }();

    if (guard_value == GUARD_MAGIC) {
      printf("Successfully verified guard value: 0x%X\n", guard_value);
    } else {
      printf("----------------- GUARD TEST FAILED -----------------\n");
    }
  }

  void test_backtrace() {
    printf("Testing backtrace functionality...\n");

    void *buffer[100];
    int size = backtrace(buffer, 100);
    char **symbols = backtrace_symbols(buffer, size);
    if (symbols) {
      printf("Backtrace symbols:\n");
      for (int i = 0; i < size; i++) {
        printf("%s\n", symbols[i]);
      }

      free(symbols);
    } else {
      printf("No backtrace symbols available.\n");
    }
  }

  #define DL_ITERATE_PHDR_MAGIC 0x87654321
  void test_dl_iterate_phdr() {
    printf("Testing custom dl_iterate_phdr hook...\n");

    int magic_number;

    int result = dl_iterate_phdr([](struct dl_phdr_info *info, size_t size, void *data) -> int {
      printf("Library: %s at address %p with %zu segments\n", info->dlpi_name, (void *)info->dlpi_addr, (size_t)info->dlpi_phnum);

      int *magic_ptr = (int *)data;
      *magic_ptr = DL_ITERATE_PHDR_MAGIC;

      return 0;
    }, &magic_number);

    if (result == 0 && magic_number == DL_ITERATE_PHDR_MAGIC) {
      printf("Successfully verified dl_iterate_phdr number: 0x%X\n", magic_number);
    } else {
      printf("----------------- DL_ITERATE_PHDR TEST FAILED -----------------\n");
    }
  }

  void test_dladdr() {
    printf("Testing custom dladdr hook...\n");

    Dl_info info;
    if (!dladdr((void*)test_dladdr, &info)) {
      printf("----------------- DLADDR TEST FAILED -----------------\n");

      return;
    }

    if (!info.dli_fname || !info.dli_saddr || !info.dli_sname) {
      printf("----------------- DLADDR TEST FAILED (NULL FIELDS) -----------------\n");

      return;
    }

    if (strstr(info.dli_fname, "shared.so") == NULL) {
      printf("----------------- DLADDR TEST FAILED (INVALID LIBRARY NAME) -----------------\n");

      return;
    }

    if (info.dli_saddr != (void *)test_dladdr) {
      printf("----------------- DLADDR TEST FAILED (INVALID FUNCTION ADDRESS) -----------------\n");

      return;
    }

    if (strcmp(info.dli_sname, "test_dladdr") != 0) {
      printf("----------------- DLADDR TEST FAILED (INVALID FUNCTION NAME) -----------------\n");

      return;
    }

    printf("Successfully verified dladdr information.\n");
  }

  void test_ldsa_throw_catch() {
    printf("Testing LDSA throw-catch capability...\n");

    try {
      throw 42;
    } catch(int x) {
      printf("Successfully caught int: %d (LSDA working for primitive types)\n", x);
    }
    
    try {
      throw std::runtime_error("LSDA test message");
    } catch(const std::exception &e) {
      printf("Successfully caught exception: %s (LSDA working for std types)\n", e.what());
    }
      
    try {
      throw std::runtime_error("Test exception with local catch");
    } catch(const std::runtime_error &e) {
      printf("Successfully caught runtime_error: %s (LSDA working for specific types)\n", e.what());
    }
    
    try {
      throw std::runtime_error("Type info test");
    } catch(const std::exception &e) {
      printf("Successfully caught exception: %s (type name: %s)\n", e.what(), typeid(e).name());
    }

    throw std::runtime_error("Uncaught exception from test_ldsa_throw_catch");
  }

  void shared_function() {
    printf("Hello from shared_function in the shared library!\n");

    test_relocation();
    test_mte();
    test_guard();
    test_backtrace();
    test_dl_iterate_phdr();
    test_dladdr();
    
    try {
      test_ldsa_throw_catch();
    } catch (const std::exception &e) {
      printf("Caught exception from test_ldsa_throw_catch: %s\n", e.what());
    }

    printf("shared_function completed.\n");
  }
}