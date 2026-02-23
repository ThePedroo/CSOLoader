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
#include <signal.h>
#include <setjmp.h>

#include <android/log.h>
#include <sys/prctl.h>

#include <typeinfo>
#include <stdexcept>

/* TODO: Implement dependency dependency test */
/* TODO: Add (de)constructor array test */

#include <pthread.h>

/* INFO: Constructor's test */
bool constructor_called = false;

/* INFO: TLS test variables */
static __thread int tls_counter = 42; /* INFO: Initialized TLS (.tdata) */
static __thread int tls_zero = 0;     /* INFO: Zero-initialized TLS (.tbss) */
static __thread char tls_buffer[64];  /* INFO: Larger TLS buffer (.tbss) */

#define TLS_MAGIC_MAIN 0xDEADBEEF
#define TLS_MAGIC_THREAD 0xCAFEBABE

struct tls_test_result {
  int thread_counter;
};

static void *tls_thread_func(void *arg) {
  tls_test_result *result = (tls_test_result *)arg;
  
  /* INFO: Verify this thread has its own copy with initial value */
  result->thread_counter = tls_counter;
  
  /* INFO: Modify in this thread. Should not affect main thread */
  tls_counter = TLS_MAGIC_THREAD;
  
  return NULL;
}

extern "C" {
  void test_constructor() {
    printf("Testing constructor functionality...\n");

    if (!constructor_called) {
      printf("----------------- CONSTRUCTOR TEST FAILED -----------------\n");

      return;
    }
    
    printf("Constructor test completed.\n");
  }
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
  
  static sigjmp_buf relro_jmp_buf;
  static volatile sig_atomic_t relro_signal_caught = 0;
  
  static ElfW(Addr) g_relro_start = 0;
  static size_t g_relro_size = 0;
  
  static void relro_signal_handler(int sig) {
    relro_signal_caught = 1;
    siglongjmp(relro_jmp_buf, 1);
  }
  
  void test_relro() {
    printf("Testing RELRO functionality...\n");

    g_relro_start = 0;
    g_relro_size = 0;
    
    dl_iterate_phdr([](struct dl_phdr_info *info, size_t size, void *data) -> int {
      if (strstr(info->dlpi_name, "shared.so") == NULL) return 0;

      for (int i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type != PT_GNU_RELRO) continue;

        g_relro_start = info->dlpi_addr + info->dlpi_phdr[i].p_vaddr;
        g_relro_size = info->dlpi_phdr[i].p_memsz;

        return 1;
      }

      return 1;
    }, NULL);
    
    if (g_relro_start == 0 || g_relro_size == 0) {
      printf("----------------- RELRO TEST FAILED (NO RELRO SECTION FOUND) -----------------");

      return;
    }
    
    struct sigaction sa, old_sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = relro_signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    if (sigaction(SIGSEGV, &sa, &old_sa) != 0) {
      printf("----------------- RELRO TEST FAILED (FAILED TO SET SIGNAL HANDLER) -----------------");

      return;
    }
    
    relro_signal_caught = 0;
    
    if (sigsetjmp(relro_jmp_buf, 1) == 0) {
      volatile char *ptr = (volatile char *)g_relro_start;
      /* INFO: If protected, kernel would signal SIGSEGV */
      *ptr = 0x42;
      
      printf("----------------- RELRO TEST FAILED (COULD WRITE TO PROTECTED SEGMENT) -----------------");
    }
    
    sigaction(SIGSEGV, &old_sa, NULL);

    printf("RELRO test completed.\n");
  }
  
  void test_tls() {
    printf("Testing Thread-Local Storage (TLS) functionality...\n");

    if (tls_counter != 42) {
      printf("----------------- TLS TEST FAILED (INITIAL VALUE WRONG: 42 VS %d) -----------------\n", tls_counter);

      return;
    }

    if (tls_zero != 0) {
      printf("----------------- TLS TEST FAILED (ZERO-INITIALIZED VALUE WRONG: 0 VS %d) -----------------\n", tls_zero);

      return;
    }

    tls_counter = TLS_MAGIC_MAIN;
    if (tls_counter != (int)TLS_MAGIC_MAIN) {
      printf("----------------- TLS TEST FAILED (MODIFIED VALUE WRONG: %d VS %d) -----------------\n", (int)TLS_MAGIC_MAIN, tls_counter);

      return;
    }

    const char *test_string = "TLS buffer test string";
    strcpy(tls_buffer, test_string);

    if (strcmp(tls_buffer, test_string) != 0) {
      printf("----------------- TLS TEST FAILED (BUFFER TEST FAILED) -----------------\n");

      return;
    }
    
    struct tls_test_result result = { 0 };

    pthread_t thread;
    if (pthread_create(&thread, NULL, tls_thread_func, &result) == 0) {
      pthread_join(thread, NULL);

      if (result.thread_counter != 42) {
        printf("----------------- TLS TEST FAILED (THREAD SAW WRONG INITIAL VALUE: 42 VS %d) -----------------\n", result.thread_counter);

        return;
      }

      if (tls_counter != (int)TLS_MAGIC_MAIN) {
        printf("----------------- TLS TEST FAILED (MAIN THREAD VALUE CORRUPTED BY SPAWNED THREAD) -----------------\n");

        return;
      }
    } else {
      printf("TLS thread test skipped: pthread_create failed\n");
    }

    printf("TLS test completed successfully.\n");
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

    test_constructor();
    test_relocation();
    test_relro();
    test_tls();
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

    printf("shared_function completed. Assure destructor is working.\n");
  }
}

/* INFO: Constructor/Deconstructor test */
__attribute__((constructor)) void csoloader_test_constructor() {
  /* TODO: At some point we might want to assure all functionality is already available by here */
  constructor_called = true;
}
 
__attribute__((destructor)) void csoloader_test_deconstructor() {
  printf("Destructor test completed.");
}