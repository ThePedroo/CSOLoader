/* Copyright (c) 2025 ThePedroo. All rights reserved.
 *
 * This source code is licensed under the GNU AGPLv3 License found in the
 * LICENSE file in the root directory of this source tree.
 */

/* TODO: Make it more closely match ReZygisk's elf utils */

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <elf.h>
#include <link.h>
#include <limits.h>

#include "carray.h"
#include "elf_util.h"
#include "logging.h"
#include "sleb128.h"
#include "backtrace-support.h"

#include "linker.h"

/* INFO: R_GENERIC_NONE is always 0 */
#define R_GENERIC_NONE 0
#ifdef __aarch64__
  #define R_GENERIC_JUMP_SLOT     R_AARCH64_JUMP_SLOT
  #define R_GENERIC_ABSOLUTE      R_AARCH64_ABS64
  #define R_GENERIC_GLOB_DAT      R_AARCH64_GLOB_DAT
  #define R_GENERIC_RELATIVE      R_AARCH64_RELATIVE
  #define R_GENERIC_IRELATIVE     R_AARCH64_IRELATIVE
  #define R_GENERIC_COPY          R_AARCH64_COPY
  #define R_GENERIC_TLS_DTPMOD    R_AARCH64_TLS_DTPMOD
  #define R_GENERIC_TLS_DTPREL    R_AARCH64_TLS_DTPREL
  #define R_GENERIC_TLS_TPREL     R_AARCH64_TLS_TPREL
  #define R_GENERIC_TLSDESC       R_AARCH64_TLSDESC
#elif defined(__arm__)
  #define R_GENERIC_JUMP_SLOT     R_ARM_JUMP_SLOT
  #define R_GENERIC_ABSOLUTE      R_ARM_ABS32
  #define R_GENERIC_GLOB_DAT      R_ARM_GLOB_DAT
  #define R_GENERIC_RELATIVE      R_ARM_RELATIVE
  #define R_GENERIC_IRELATIVE     R_ARM_IRELATIVE
  #define R_GENERIC_COPY          R_ARM_COPY
  #define R_GENERIC_TLS_DTPMOD    R_ARM_TLS_DTPMOD32
  #define R_GENERIC_TLS_DTPREL    R_ARM_TLS_DTPOFF32
  #define R_GENERIC_TLS_TPREL     R_ARM_TLS_TPOFF32
  #define R_GENERIC_TLSDESC       R_ARM_TLS_DESC
#elif defined(__i386__)
  #define R_GENERIC_JUMP_SLOT     R_386_JMP_SLOT
  #define R_GENERIC_ABSOLUTE      R_386_32
  #define R_GENERIC_GLOB_DAT      R_386_GLOB_DAT
  #define R_GENERIC_RELATIVE      R_386_RELATIVE
  #define R_GENERIC_IRELATIVE     R_386_IRELATIVE
  #define R_GENERIC_COPY          R_386_COPY
  #define R_GENERIC_TLS_DTPMOD    R_386_TLS_DTPMOD32
  #define R_GENERIC_TLS_DTPREL    R_386_TLS_DTPOFF32
  #define R_GENERIC_TLS_TPREL     R_386_TLS_TPOFF
  #define R_GENERIC_TLSDESC       R_386_TLS_DESC
#elif defined (__riscv)
  #define R_GENERIC_JUMP_SLOT     R_RISCV_JUMP_SLOT
  #define R_GENERIC_ABSOLUTE      R_RISCV_64
  #define R_GENERIC_GLOB_DAT      R_RISCV_64
  #define R_GENERIC_RELATIVE      R_RISCV_RELATIVE
  #define R_GENERIC_IRELATIVE     R_RISCV_IRELATIVE
  #define R_GENERIC_COPY          R_RISCV_COPY
  #define R_GENERIC_TLS_DTPMOD    R_RISCV_TLS_DTPMOD64
  #define R_GENERIC_TLS_DTPREL    R_RISCV_TLS_DTPREL64
  #define R_GENERIC_TLS_TPREL     R_RISCV_TLS_TPREL64
  #define R_GENERIC_TLSDESC       R_RISCV_TLSDESC
#elif defined (__x86_64__)
  #define R_GENERIC_JUMP_SLOT     R_X86_64_JUMP_SLOT
  #define R_GENERIC_ABSOLUTE      R_X86_64_64
  #define R_GENERIC_GLOB_DAT      R_X86_64_GLOB_DAT
  #define R_GENERIC_RELATIVE      R_X86_64_RELATIVE
  #define R_GENERIC_IRELATIVE     R_X86_64_IRELATIVE
  #define R_GENERIC_COPY          R_X86_64_COPY
  #define R_GENERIC_TLS_DTPMOD    R_X86_64_DTPMOD64
  #define R_GENERIC_TLS_DTPREL    R_X86_64_DTPOFF64
  #define R_GENERIC_TLS_TPREL     R_X86_64_TPOFF64
  #define R_GENERIC_TLSDESC       R_X86_64_TLSDESC
#endif

#if !defined(ELF_R_SYM) || !defined(ELF_R_TYPE)
  #ifdef __LP64__
    #define ELF_R_SYM ELF64_R_SYM
    #define ELF_R_TYPE ELF64_R_TYPE
  #else
    #define ELF_R_SYM ELF32_R_SYM
    #define ELF_R_TYPE ELF32_R_TYPE
  #endif
#endif

static size_t system_page_size = 0;

/* INFO: Internal functions START */

int g_argc = 0;
char **g_argv = NULL;
char **g_envp = NULL;

static void _linker_call_preinit_constructors(ElfImg *img) {
  if (!img->preinit_array) return;

  LOGD("Calling .preinit_array constructors for %s", img->elf);
  for (size_t i = 0; i < img->preinit_array_count; ++i) {
    LOGD("Calling preinit_array[%zu] at %p", i, img->preinit_array[i]);

    img->preinit_array[i](g_argc, g_argv, g_envp);
  }
}

static void _linker_call_constructors(ElfImg *img) {
  if (img->init_func) {
    LOGD("Calling .init function for %s at %p", img->elf, img->init_func);

    img->init_func();
  }

  if (img->init_array) {
    LOGD("Calling .init_array constructors for %s", img->elf);

    for (size_t i = 0; i < img->init_array_count; ++i) {
      LOGD("Calling init_array[%zu] at %p", i, img->init_array[i]);

      img->init_array[i](g_argc, g_argv, g_envp);
    }
  }
}

static void _linker_call_destructors(ElfImg *img) {
  if (img->fini_array) {
    LOGD("Calling .fini_array destructors for %s", img->elf);

    for (size_t i = img->fini_array_count; i > 0; --i) {
      LOGD("Calling fini_array[%zu] at %p", i - 1, img->fini_array[i - 1]);

      img->fini_array[i - 1]();
    }
  }

  if (img->fini_func) {
    LOGD("Calling .fini function for %s at %p", img->elf, img->fini_func);

    img->fini_func();
  }
}

static void _linker_internal_init() {
  if (system_page_size != 0) return;

  system_page_size = sysconf(_SC_PAGESIZE);
  if (system_page_size <= 0) {
    LOGE("Failed to get system page size");

    return;
  }

  LOGD("System page size: %zu bytes", system_page_size);
}

static inline uintptr_t _page_start(uintptr_t addr) {
  return addr & ~(system_page_size - 1);
}

static inline uintptr_t _page_end(uintptr_t addr) {
  return _page_start(addr + system_page_size - 1);
}

static bool _linker_find_library_path(const char *lib_name, char *full_path, size_t full_path_size) {
  const char *search_paths[] = {
    #ifdef __LP64__
      #ifdef __ANDROID__
        "/apex/com.android.runtime/lib64/bionic/",
        "/apex/com.android.runtime/lib64/",
        "/system/lib64/",
        "/vendor/lib64/",
      #else
        "/lib64/",
        "/usr/lib64/",
        "/lib/x86_64-linux-gnu/",
        "/usr/lib/x86_64-linux-gnu/",
      #endif
    #else
      #ifdef __ANDROID__
        "/apex/com.android.runtime/lib/bionic/",
        "/apex/com.android.runtime/lib/",
        "/system/lib/",
        "/vendor/lib/",
      #else
        "/lib/",
        "/usr/lib/",
        "/lib/i386-linux-gnu/",
      #endif
    #endif
    "/usr/local/lib/",
    NULL
  };

  if (strcmp(lib_name, "libc++.so") == 0) {
    LOGD("Forced replacement for using /system/lib64 for libc++.so");

    snprintf(full_path, full_path_size, "/system/lib64/%s", lib_name);

    return true;
  }

  for (int i = 0; search_paths[i] != NULL; ++i) {
    snprintf(full_path, full_path_size, "%s%s", search_paths[i], lib_name);

    if (access(full_path, F_OK) == 0) return true;
  }

  LOGE("Could not find library which shared library depends on: %s", lib_name);
  full_path[0] = '\0';

  return false;
}

/* INFO: Internal functions END */

bool linker_init(struct linker *linker, ElfImg *img) {
  _linker_internal_init();

  linker->img = img;
  linker->is_linked = false;
  linker->dep_count = 0;

  for (int i = 0; i < MAX_DEPS; ++i) {
    linker->dependencies[i].img = NULL;
    linker->dependencies[i].is_manual_load = false;
    linker->dependencies[i].file_vaddr_base = 0;
  }

  return true;
}

void linker_destroy(struct linker *linker) {
  if (linker->is_linked) {
    LOGD("Unregistering libraries from backtrace support");

    for (int i = linker->dep_count - 1; i >= 0; --i) {
      if (linker->dependencies[i].img && linker->dependencies[i].is_manual_load) {
        unregister_eh_frame_for_library(linker->dependencies[i].img);
        unregister_custom_library_for_backtrace(linker->dependencies[i].img);
        _linker_call_destructors(linker->dependencies[i].img);
      }
    }

    unregister_eh_frame_for_library(linker->img);
    unregister_custom_library_for_backtrace(linker->img);
    _linker_call_destructors(linker->img);
  }

  for (int i = 0; i < linker->dep_count; i++) {
    if (!linker->dependencies[i].img) continue;

    void *base = linker->dependencies[i].img->base;
    size_t size = linker->dependencies[i].img->size;

    ElfImg_destroy(linker->dependencies[i].img);

    if (linker->dependencies[i].is_manual_load) munmap(base, size);
  }

  linker->dep_count = 0;
}

static size_t phdr_get_load_size(const ElfW(Phdr) *phdr, size_t cnt, ElfW(Addr) *min_vaddr) {
  ElfW(Addr) lo = UINTPTR_MAX, hi = 0;
  for (size_t i = 0; i < cnt; ++i) {
    if (phdr[i].p_type != PT_LOAD) continue;

    if (phdr[i].p_vaddr < lo) lo = phdr[i].p_vaddr;
    if (phdr[i].p_vaddr + phdr[i].p_memsz > hi) hi = phdr[i].p_vaddr + phdr[i].p_memsz;
  }

  lo = _page_start(lo);
  hi = _page_end(hi);

  if (min_vaddr) *min_vaddr = lo;

  return hi - lo;
}

static int _linker_load_one_segment(int fd, ElfW(Phdr)* phdr,
                            ElfW(Addr) bias, off_t file_off) {
  ElfW(Addr) seg_start = phdr->p_vaddr + bias;
  ElfW(Addr) seg_end = seg_start + phdr->p_memsz;

  ElfW(Addr) page_start = _page_start(seg_start);
  ElfW(Addr) page_end = _page_end(seg_end);

  ElfW(Addr) file_page =_page_start(phdr->p_offset);
  size_t file_len = _page_end(phdr->p_offset + phdr->p_filesz) - file_page;

  int prot = 0;
  if (phdr->p_flags & PF_R) prot |= PROT_READ;
  if (phdr->p_flags & PF_W) prot |= PROT_WRITE;
  if (phdr->p_flags & PF_X) prot |= PROT_EXEC;

  /* INFO: If it needs WRITE, then mmap without it, and later add that
             permission to avoid issues. */
  bool needs_mprotect = false;
  if ((prot & PROT_WRITE) && (prot & PROT_EXEC)) {
    needs_mprotect = true;

    prot &= ~PROT_EXEC;
  }

  /* INFO: mmap with PROT_WRITE on modern Android gives "Invalid argument" error */
  if (file_len > 0 && mmap((void *)page_start, file_len, prot, MAP_FIXED | MAP_PRIVATE, fd, file_off + file_page) == MAP_FAILED) {
    PLOGE("mmap file-backed segment");

    return -1;
  }

  /* INFO: mmap the anonymous BSS portion that extends beyond the file size */
  if (page_end > page_start + file_len) {
    void *bss_addr = (void *)(page_start + file_len);
    size_t bss_size = page_end - (page_start + file_len);

    if (mmap(bss_addr, bss_size, prot, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == MAP_FAILED) {
      PLOGE("mmap anonymous BSS segment");

      return -1;
    }
  }

  /* INFO: This is needed to avoid access to uninitialized data */
  if ((phdr->p_flags & PF_W) != 0) {
    ElfW(Addr) file_end = seg_start + phdr->p_filesz;

    /* INFO: Check if file_end is within the mapped range and it's not aligned
               to the page boundary. */
    if (file_end < page_end && (file_end % system_page_size) != 0) {
      // Zero from the end of the file data to the next page boundary.
      memset((void *)file_end, 0, system_page_size - (file_end % system_page_size));
    }
  }

  /* INFO: Restore PROT_EXEC if it was removed earlier */
  if (needs_mprotect && mprotect((void*)page_start, page_end - page_start, prot | PROT_EXEC) != 0) {
    PLOGE("mprotect to add PROT_EXEC");

    return -1;
  }

  return 0;
}

void *linker_load_library_manually(const char *lib_path, struct loaded_dep *out) {
  _linker_internal_init();

  int fd = open(lib_path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    PLOGE("open %s", lib_path);

    return NULL;
  }

  ElfW(Ehdr) eh;
  if (pread(fd, &eh, sizeof eh, 0) != sizeof eh) {
    LOGE("Failed to read ELF header from %s", lib_path);

    close(fd);

    return NULL;
  }

  const size_t phdr_sz = eh.e_phnum * sizeof(ElfW(Phdr));
  ElfW(Phdr) *phdr = malloc(phdr_sz);
  if (!phdr) {
    LOGE("Failed to allocate memory for program headers from %s", lib_path);

    close(fd);

    return NULL;
  }

  if (pread(fd, phdr, phdr_sz, eh.e_phoff) != (ssize_t)phdr_sz) {
    LOGE("Failed to read program headers from %s", lib_path);

    close(fd);

    free(phdr);

    return NULL;
  }

  ElfW(Addr) min_vaddr;
  size_t load_size = phdr_get_load_size(phdr, eh.e_phnum, &min_vaddr);
  if (load_size == 0) {
    LOGE("No loadable segments found in ELF headers");

    close(fd);

    free(phdr);

    return NULL;
  }

  /* One PROT_NONE hole big enough for everything */
  void *base = mmap(NULL, load_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (base == MAP_FAILED) {
    LOGE("Failed to reserve address space: %s", strerror(errno));

    close(fd);

    free(phdr);

    return NULL;
  }

  ElfW(Addr) bias = (ElfW(Addr))base - min_vaddr;

  /* INFO: Load all segments to the reserved address space */
  for (int i = 0; i < eh.e_phnum; i++) {
    if (phdr[i].p_type != PT_LOAD) continue;

    if (_linker_load_one_segment(fd, &phdr[i], bias, 0) != 0) {
      LOGE("Failed to load segment %d of %s", i, lib_path);

      munmap(base, load_size);

      close(fd);

      free(phdr);

      return NULL;
    }
  }

  close(fd);

  out->is_manual_load = true;
  out->file_vaddr_base = _page_start(phdr[0].p_vaddr);
  out->load_bias = bias;

  free(phdr);

  return base;
}

struct linker_symbol_info {
  void *addr;
  ElfImg *img;
};

static struct linker_symbol_info _linker_find_symbol_in_linker_scope(struct linker *linker, const char *sym_name) {
  void *addr = (void *)getSymbAddress(linker->img, sym_name);
  if (addr) {
    LOGD("Found symbol '%s' in main image: %s via Elf Utils: %p",
          sym_name, linker->img->elf, addr);

    return (struct linker_symbol_info) {
      .addr = addr,
      .img = linker->img
    };
  }

  for (int i = 0; i < linker->dep_count; i++) {
    addr = (void *)getSymbAddress(linker->dependencies[i].img, sym_name);
    if (!addr) continue;

    LOGD("Found symbol '%s' in dependency %d: %s via Elf Utils: %p",
         sym_name, i, linker->dependencies[i].img->elf, addr);

    return (struct linker_symbol_info) {
      .addr = addr,
      .img = linker->dependencies[i].img
    };
  }

  LOGE("Symbol '%s' not found in any loaded image", sym_name);

  return (struct linker_symbol_info) {
    .addr = NULL,
    .img = NULL
  };
}

/* TODO: Avoid repetition here */
#ifdef __aarch64__
  /* INFO: Struct containing information about hardware capabilities used in resolver. This
             struct information is pulled directly from the AOSP code.

     SOURCES:
      - https://android.googlesource.com/platform/bionic/+/refs/tags/android-16.0.0_r1/libc/include/sys/ifunc.h#53
  */
  struct __ifunc_arg_t {
    unsigned long _size;
    unsigned long _hwcap;
    unsigned long _hwcap2;
  };

  /* INFO: This is a constant used in the AOSP code to indicate that the struct __ifunc_arg_t
             contains hardware capabilities.

     SOURCES:
      - https://android.googlesource.com/platform/bionic/+/refs/tags/android-16.0.0_r1/libc/include/sys/ifunc.h#74
  */
  #define _IFUNC_ARG_HWCAP (1ULL << 62)
#elif defined(__riscv)
  /* INFO: Struct used in Linux RISC-V architecture to probe hardware capabilities.

     SOURCES:
      - https://android.googlesource.com/platform/bionic/+/refs/tags/android-16.0.0_r1/libc/kernel/uapi/asm-riscv/asm/hwprobe.h#10
  */
  struct riscv_hwprobe {
    int64_t key;
    uint64_t value;
  };

  /* INFO: This function is used in the AOSP code to probe hardware capabilities on RISC-V architecture
             by calling the syscall __NR_riscv_hwprobe and passing the parameters that will filled with
             the device hardware capabilities.

     SOURCES:
      - https://android.googlesource.com/platform/bionic/+/refs/tags/android-16.0.0_r1/libc/bionic/vdso.cpp#86
  */
  int __riscv_hwprobe(struct riscv_hwprobe *pairs, size_t pair_count, size_t cpu_count, unsigned long *cpus, unsigned flags) {
    register long a0 __asm__("a0") = (long)pairs;
    register long a1 __asm__("a1") = pair_count;
    register long a2 __asm__("a2") = cpu_count;
    register long a3 __asm__("a3") = (long)cpus;
    register long a4 __asm__("a4") = flags;
    register long a7 __asm__("a7") = __NR_riscv_hwprobe;

    __asm__ volatile(
      "ecall"
      : "=r"(a0)
      : "r"(a0), "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a7)
    );

    return -a0;
  }

  /* INFO: This is a function pointer type that points how the signature of the __riscv_hwprobe
             function is.

     SOURCES:
      - https://android.googlesource.com/platform/bionic/+/refs/tags/android-16.0.0_r1/libc/include/sys/hwprobe.h#62
  */
  typedef int (*__riscv_hwprobe_t)(struct riscv_hwprobe *__pairs, size_t __pair_count, size_t __cpu_count, unsigned long *__cpus, unsigned __flags);
#endif

/* INFO: GNU ifuncs (indirect functions) are functions that does not execute the code by itself,
           but instead lead to other functions that may very according to hardware capabilities,
           or other reasons, depending of the architecture.

         This function is based on AOSP's (Android Open Source Project) code, and resolves the
           indirect symbol, leading to the correct, most appropriate for the hardware, symbol.

    SOURCES: 
     - https://android.googlesource.com/platform/bionic/+/refs/tags/android-16.0.0_r1/linker/linker.cpp#2594
     - https://android.googlesource.com/platform/bionic/+/tags/android-16.0.0_r1/libc/bionic/bionic_call_ifunc_resolver.cpp#41
*/
ElfW(Addr) handle_indirect_symbol(uintptr_t resolver_addr) {
  #ifdef __aarch64__
    typedef ElfW(Addr) (*ifunc_resolver_t)(uint64_t, struct __ifunc_arg_t *);

    struct __ifunc_arg_t args = {
      ._size = sizeof(struct __ifunc_arg_t),
      ._hwcap = getauxval(AT_HWCAP),
      ._hwcap2 = getauxval(AT_HWCAP2)
    };

    return ((ifunc_resolver_t)resolver_addr)(args._hwcap | _IFUNC_ARG_HWCAP, &args);
  #elif defined(__arm__)
      typedef ElfW(Addr) (*ifunc_resolver_t)(unsigned long);

      return ((ifunc_resolver_t)resolver_addr)(getauxval(AT_HWCAP));
  #elif defined(__riscv)
    typedef ElfW(Addr) (*ifunc_resolver_t)(uint64_t, __riscv_hwprobe_t, void *);

    return ((ifunc_resolver_t)resolver_addr)(getauxval(AT_HWCAP), __riscv_hwprobe, NULL);
  #else
    typedef ElfW(Addr) (*ifunc_resolver_t)(void);

    return ((ifunc_resolver_t)resolver_addr)();
  #endif
}

#define MAX_TLS_MODULES 128
struct tls_module {
  size_t module_id;
  size_t align;
  size_t memsz;
  size_t filesz;
  size_t offset;
  const void *init_image;
  ElfImg  *owner;
};

static struct tls_module g_tls_modules[MAX_TLS_MODULES];
/* INFO: "dlopen" counter for (future) TLS modules. */
static size_t            g_tls_generation       = 0;
static size_t            g_tls_static_size      = 0;
static size_t            g_tls_static_align_max = 1;

static bool _linker_register_tls_segment(ElfImg *img) {
  if (!img->tls_segment) return true;

  size_t mod_id;
  for (mod_id = 1; mod_id < MAX_TLS_MODULES; mod_id++) {
    if (g_tls_modules[mod_id].module_id == 0) break;
  }

  if (mod_id == MAX_TLS_MODULES) {
    LOGE("TLS module overflow");

    return false;
  }

  struct tls_module *m = &g_tls_modules[mod_id];
  m->module_id  = mod_id;
  m->align      = img->tls_segment->p_align ? img->tls_segment->p_align : 1;
  m->memsz      = img->tls_segment->p_memsz;
  m->filesz     = img->tls_segment->p_filesz;
  m->init_image = (const void *)((uintptr_t)img->base + img->tls_segment->p_vaddr - img->bias);
  m->owner      = img;

  #ifndef ALIGN_UP
    #define ALIGN_UP(x, a)  ( ((x) + ((a) - 1)) & ~((a) - 1) )
  #endif

  g_tls_static_size      = ALIGN_UP(g_tls_static_size, m->align);
  m->offset              = g_tls_static_size;
  g_tls_static_size     += m->memsz;
  if (m->align > g_tls_static_align_max)
    g_tls_static_align_max = m->align;

  img->tls_mod_id = mod_id;

  return true;
}

static pthread_key_t g_tls_key;
static pthread_once_t g_tls_key_once = PTHREAD_ONCE_INIT;

static void _linker_alloc_tls_key_once(void) {
  pthread_key_create(&g_tls_key, free);
}

void *_linker_allocate_tls_for_thread(void) {
  pthread_once(&g_tls_key_once, _linker_alloc_tls_key_once);

  uint8_t *block = calloc(1, g_tls_static_size + g_tls_static_align_max);
  if (!block) return NULL;

  for (size_t i = 1; i < MAX_TLS_MODULES; ++i) {
    if (!g_tls_modules[i].module_id) continue;

    memcpy(block + g_tls_modules[i].offset, g_tls_modules[i].init_image, g_tls_modules[i].filesz);
  }

  pthread_setspecific(g_tls_key, block);

  return block;
}

__attribute__((constructor)) static void _linker_setup_initial_tls(void) {
  LOGD("Setting up initial TLS for main thread");

  _linker_allocate_tls_for_thread();
}

__attribute__((destructor)) static void _linker_cleanup_initial_tls(void) {
  LOGD("Cleaning up initial TLS for main thread");

  free(pthread_getspecific(g_tls_key));
  pthread_setspecific(g_tls_key, NULL);
}

static inline void *_linker_tls_block_for_current_thread(void) {
  void *p = pthread_getspecific(g_tls_key);
  if (!p) {
    LOGD("No TLS block found for current thread %llu, allocating new one", (unsigned long long)pthread_self());

    p = _linker_allocate_tls_for_thread();
  }

  return p;
}

/* INFO: This structure is used to access thread-local storage (TLS) variables. 
           It cannot and should not have its members modified.  */
struct tls_index {
  unsigned long module;
  unsigned long offset;
};

void *__tls_get_addr(struct tls_index *ti) {
  void *block = _linker_tls_block_for_current_thread();
  if (!block) {
    LOGE("Library tried to access TLS, but allocation failed");

    return NULL;
  }

  size_t mod_id = ti->module;
  if (mod_id == 0 || mod_id >= MAX_TLS_MODULES || g_tls_modules[mod_id].module_id == 0) {
    LOGE("Library tried to access invalid TLS module ID %lu", mod_id);

    return NULL;
  }

  return (uint8_t *)block + g_tls_modules[mod_id].offset + ti->offset;
}

struct _linker_unified_r {
  uint32_t sym_idx;
  uint32_t type;
  ElfW(Addr) r_offset;
  ElfW(Addr) r_addend;
};

static void _linker_process_unified_relocation(struct linker *linker, ElfImg *image, struct _linker_unified_r *r, ElfW(Addr) load_bias, ElfW(Sym) *dynsym, char *dynstr, bool is_rela) {
  ElfW(Addr) *target_addr = (ElfW(Addr) *)(load_bias + r->r_offset);

  switch (r->type) {
    case R_GENERIC_NONE: {
      LOGD("Skipping R_GENERIC_NONE relocation at %p in %s", target_addr, image->elf);

      break;
    }
    case R_GENERIC_COPY: {
      LOGW("R_GENERIC_COPY relocation at %p in %s: This relocation type is not supported yet",
           target_addr, image->elf);

      break;
    }
    case R_GENERIC_IRELATIVE: {
      *target_addr = handle_indirect_symbol(load_bias + (is_rela ? r->r_addend : *(ElfW(Addr) *)(target_addr)));

      LOGD("R_GENERIC_IRELATIVE relocation at %p in %s: Resolved to %p",
           target_addr, image->elf, (void *)*target_addr);
      break;
    }
    case R_GENERIC_RELATIVE: {
      *target_addr = load_bias + (is_rela ? r->r_addend : *(ElfW(Addr) *)(target_addr));

      LOGD("R_GENERIC_RELATIVE relocation at %p in %s: Resolved to %p",
           target_addr, image->elf, (void *)*target_addr);
      break;
    }
    case R_GENERIC_GLOB_DAT:
    case R_GENERIC_ABSOLUTE:
    case R_GENERIC_JUMP_SLOT:
    case R_GENERIC_TLS_DTPMOD:
    case R_GENERIC_TLS_DTPREL:
    case R_GENERIC_TLS_TPREL:
    #ifdef __x86_64__
      case R_X86_64_32:
      case R_X86_64_PC32:
    #elif defined(__i386__)
      case R_386_PC32:
    #endif
    {
      const char *sym_name = dynstr + dynsym[r->sym_idx].st_name;
      struct linker_symbol_info sym = _linker_find_symbol_in_linker_scope(linker, sym_name);
      if (!sym.addr) {
        LOGE("Symbol '%s' not found for relocation in %s", sym_name, image->elf);

        return;
      }

      if (strcmp(sym_name, "dl_iterate_phdr") == 0) {
        LOGD("Special case for dl_iterate_phdr: using linker->img->base instead of sym.addr");

        *target_addr = custom_dl_iterate_phdr;

        return;
      }

      if (strcmp(sym_name, "dladdr") == 0) {
        LOGD("Special case for dladdr: using linker->img->base instead of sym.addr");

        *target_addr = custom_dladdr;

        return;
      }

      switch (r->type) {
        case R_GENERIC_GLOB_DAT:
        case R_GENERIC_ABSOLUTE:
        case R_GENERIC_JUMP_SLOT: {
          *target_addr = (ElfW(Addr))sym.addr + (r->type == R_GENERIC_ABSOLUTE && is_rela ? *(ElfW(Addr) *)target_addr : 0);

          LOGD("%s relocation at %p in %s: symbol '%s' resolved to %p",
               r->type == R_GENERIC_GLOB_DAT ? "R_GENERIC_GLOB_DAT" :
               r->type == R_GENERIC_ABSOLUTE ? "R_GENERIC_ABSOLUTE" :
               r->type == R_GENERIC_JUMP_SLOT ? "R_GENERIC_JUMP_SLOT" : "Unknown",
               target_addr, image->elf, sym_name, (void *)*target_addr);

          break;
        }
        /* TODO: This TLS implementation is a SHIT and wrong */
        case R_GENERIC_TLS_DTPMOD: {
          LOGF("Broken!");

          *target_addr = sym.img->tls_segment ? sym.img->tls_mod_id : 0;

          LOGD("TLS: R_GENERIC_TLS_DTPMOD relocation at %p in %s: symbol '%s' resolved to module ID %p",
               target_addr, image->elf, sym_name, (void *)*target_addr);

          break;
        }
        case R_GENERIC_TLS_DTPREL: {
          LOGF("Broken!");

          *target_addr = r->r_addend;

          LOGD("TLS: R_GENERIC_TLS_DTPREL relocation at %p in %s: symbol '%s' resolved to addend %p",
               target_addr, image->elf, sym_name, (void *)*target_addr);

          break;
        }
        case R_GENERIC_TLS_TPREL: {
          LOGF("Broken!");

          *target_addr = (ElfW(Addr))sym.addr + r->r_addend - (ElfW(Addr))_linker_tls_block_for_current_thread();

          LOGD("TLS: R_GENERIC_TLS_TPREL relocation at %p in %s: symbol '%s' resolved to %p",
               target_addr, image->elf, sym_name, (void *)*target_addr);

          break;
        }
        #ifdef __x86_64__
        case R_X86_64_32: {
          *target_addr = (ElfW(Addr))sym.addr + r->r_addend;

          LOGD("R_X86_64_32 relocation at %p in %s: symbol '%s' resolved to %p",
               target_addr, image->elf, sym_name, (void *)*target_addr);

          break;
        }
        case R_X86_64_PC32: {
          *target_addr = (ElfW(Addr))sym.addr + r->r_addend - (ElfW(Addr))target_addr;

          LOGD("R_X86_64_PC32 relocation at %p in %s: symbol '%s' resolved to %p",
               target_addr, image->elf, sym_name, (void *)*target_addr);

          break;
        }
        #elif defined(__i386__)
        case R_386_PC32: {
          *target_addr = (ElfW(Addr))sym.addr + (is_rela ? *(ElfW(Addr) *)(target_addr) : r->r_addend) - (ElfW(Addr))target_addr;

          LOGD("R_386_PC32 relocation at %p in %s: symbol '%s' resolved to %p",
               target_addr, image->elf, sym_name, (void *)*target_addr);

          break;
        }
        #endif
      }
      break;
    }
    default: {
      LOGF("Unsupported relocation type: %d in %s.\n - Symbol index: %d\n - Symbol name: %s\n - Offset: %p\n - Addend: %p",
           r->type, image->elf, r->sym_idx, dynstr + dynsym[r->sym_idx].st_name,
           target_addr, (void *)r->r_addend);
    }
  }
}

static void _linker_process_relocations(struct linker *linker, ElfImg *image) {
  ElfW(Phdr) *phdr = (ElfW(Phdr) *)((uintptr_t)image->header + image->header->e_phoff);
  ElfW(Dyn) *dyn = NULL;
  for (int i = 0; i < image->header->e_phnum; i++) {
    if (phdr[i].p_type != PT_DYNAMIC) continue;

    dyn = (ElfW(Dyn) *)((uintptr_t)image->base + phdr[i].p_vaddr - image->bias);

    break;
  }

  if (!dyn) {
    LOGD("No DYNAMIC section found in %s", image->elf);

    return;
  }

  /* TODO: Add support for RELRO */
  /* TODO: (CRITICAL) Add support for MTE to allow linker to link
             in arm v9 devices, without a crash. */

  /* INFO: Variables for non-Android RELA reallocations */
  ElfW(Rela) *rela = NULL;
  size_t rela_sz = 0;
  size_t rela_ent = 0;
  void *jmprel = NULL;
  size_t jmprel_sz = 0;

  /* INFO: Variables for non-Android REL relocations */
  ElfW(Rel) *rel = NULL;
  size_t rel_sz = 0;
  size_t rel_ent = 0;

  /* INFO: Variables RELR relocations */
  ElfW(Addr) *relr = NULL;
  size_t relr_sz = 0;

  #ifdef __ANDROID__
    bool is_rela = false;

    /* INFO: Variables for Android-specific RELA relocations */
    void *android_reloc = NULL;
    size_t android_reloc_sz = 0;
  #endif

  ElfW(Sym) *dynsym = NULL;
  char *dynstr = NULL;
  int pltrel_type = 0;
  ElfW(Addr) load_bias = (ElfW(Addr))image->base - image->bias;

  for (ElfW(Dyn) *d = dyn; d->d_tag != DT_NULL; ++d) {
    uintptr_t ptr_val = (uintptr_t)image->base + d->d_un.d_ptr - image->bias;

    switch (d->d_tag) {
      case DT_RELA:           rela = (ElfW(Rela) *)ptr_val; break;
      case DT_RELASZ:         rela_sz = d->d_un.d_val; break;
      case DT_RELAENT:        rela_ent = d->d_un.d_val; break;
      case DT_REL:            rel = (ElfW(Rel) *)ptr_val; break;
      case DT_RELSZ:          rel_sz = d->d_un.d_val; break;
      case DT_RELENT:         rel_ent = d->d_un.d_val; break;
      case DT_RELR:           relr = (ElfW(Addr) *)ptr_val; break;
      case DT_RELRSZ:         relr_sz = d->d_un.d_val; break;
      case DT_JMPREL:         jmprel = (void *)ptr_val; break;
      case DT_PLTRELSZ:       jmprel_sz = d->d_un.d_val; break;
      case DT_PLTREL:         pltrel_type = d->d_un.d_val; break;
      case DT_SYMTAB:         dynsym = (ElfW(Sym) *)ptr_val; break;
      case DT_STRTAB:         dynstr = (char *)ptr_val; break;

      #ifdef __ANDROID__
        case DT_ANDROID_RELA:   android_reloc = (void *)ptr_val; is_rela = true; break;
        case DT_ANDROID_RELASZ: android_reloc_sz = d->d_un.d_val; break;
        case DT_ANDROID_REL:    android_reloc = (void *)ptr_val; break;
        case DT_ANDROID_RELSZ:  android_reloc_sz = d->d_un.d_val; break;
      #endif
    }
  }

  if (!dynsym || !dynstr) {
    LOGE("Could not find DT_SYMTAB or DT_STRTAB in %s", image->elf);

    return;
  }

  if (relr) {
    LOGD("Processing RELR relocations for %s", image->elf);

    ElfW(Addr) *relr_entries = relr;
    size_t relr_count = relr_sz / sizeof(ElfW(Addr));
    ElfW(Addr) load_bias = (ElfW(Addr))image->base - image->bias;
    ElfW(Addr) base_offset = 0; 

    for (size_t i = 0; i < relr_count; i++) {
      ElfW(Addr) entry = relr_entries[i];

      /* INFO: Even entries are addresses */
      if ((entry & 1) == 0) {
        ElfW(Addr) reloc_offset = entry;
        ElfW(Addr) *target_addr = (ElfW(Addr) *)(load_bias + reloc_offset);
        *target_addr += load_bias;

        base_offset = reloc_offset + sizeof(ElfW(Addr));
        LOGD("RELR direct relocation at offset 0x%llx", (unsigned long long)reloc_offset);

        continue;
      }

      /* INFO: Odd entries are bitmaps */
      ElfW(Addr) current_offset = base_offset;
      entry >>= 1; /* INFO: Skip the LSB which is 1 */
      while (entry != 0) {
        if ((entry & 1) != 0) {
          ElfW(Addr) *target_addr = (ElfW(Addr) *)(load_bias + current_offset);
          *target_addr += load_bias;

          LOGD("RELR bitmap relocation at offset 0x%llx", (unsigned long long)current_offset);
        }

        current_offset += sizeof(ElfW(Addr));
        entry >>= 1;
      }

      /* INFO: After processing a bitmap, advance the base for the next one */
      base_offset += (8 * sizeof(ElfW(Addr)) - 1) * sizeof(ElfW(Addr));
    }
  }

  if (rela) {
    LOGD("Processing RELA relocations for %s", image->elf);

    if (rela_ent == 0) rela_ent = sizeof(ElfW(Rela));

    for (size_t i = 0; i < rela_sz / rela_ent; ++i) {
      ElfW(Rela) *r = &rela[i];

      struct _linker_unified_r unified_r = {
        .sym_idx = ELF_R_SYM(r->r_info),
        .type = ELF_R_TYPE(r->r_info),
        .r_offset = r->r_offset,
        .r_addend = r->r_addend
      };

      _linker_process_unified_relocation(linker, image, &unified_r, load_bias, dynsym, dynstr, true);
    }
  }

  if (rel) {
    LOGD("Processing REL relocations for %s", image->elf);

    if (rel_ent == 0) rel_ent = sizeof(ElfW(Rel));

    for (size_t i = 0; i < rel_sz / rel_ent; ++i) {
      ElfW(Rel) *r = &rel[i];

      struct _linker_unified_r unified_r = {
        .sym_idx = ELF_R_SYM(r->r_info),
        .type = ELF_R_TYPE(r->r_info),
        .r_offset = r->r_offset,
        .r_addend = 0
      };

      _linker_process_unified_relocation(linker, image, &unified_r, load_bias, dynsym, dynstr, false);
    }
  }

  #ifdef __ANDROID__
    if (android_reloc) {
      LOGD("Processing Android %s relocations for %s", is_rela ? "RELA" : "REL", image->elf);

      if (memcmp(android_reloc, "APS2", 4) != 0) {
        LOGE("Invalid Android %s magic in %s", is_rela ? "RELA" : "REL", image->elf);

        return;
      }

      const uint8_t *packed_data = (const uint8_t *)android_reloc + 4;
      size_t packed_size = android_reloc_sz - 4;

      sleb128_decoder decoder;
      sleb128_decoder_init(&decoder, packed_data, packed_size);

      uint64_t num_relocs = sleb128_decode(&decoder);

      LOGD("Number of relocations: %llu", (unsigned long long)num_relocs);

      struct _linker_unified_r unified_r = {
        .r_offset = sleb128_decode(&decoder),
      };

      for (uint64_t i = 0; i < num_relocs; ) {
        uint64_t group_size = sleb128_decode(&decoder);
        uint64_t group_flags = sleb128_decode(&decoder);

        size_t group_r_offset_delta = 0;

        const size_t RELOCATION_GROUPED_BY_INFO_FLAG = 1;
        const size_t RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG = 2;
        const size_t RELOCATION_GROUPED_BY_ADDEND_FLAG = 4;
        const size_t RELOCATION_GROUP_HAS_ADDEND_FLAG = 8;

        if (group_flags & RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG) {
          group_r_offset_delta = sleb128_decode(&decoder);

          LOGD("Group %llu: Offset delta: %llu", (unsigned long long)i, (unsigned long long)group_r_offset_delta);
        }

        if (group_flags & RELOCATION_GROUPED_BY_INFO_FLAG) {
          ElfW(Addr) r_info = sleb128_decode(&decoder);
          unified_r.sym_idx = ELF_R_SYM(r_info);
          unified_r.type = ELF_R_TYPE(r_info);

          LOGD("Group %llu: r_info: %llu, sym_idx: %u, type: %u", (unsigned long long)i, (unsigned long long)r_info, unified_r.sym_idx, unified_r.type);
        }

        size_t group_flags_reloc;
        if (is_rela) {
          group_flags_reloc = group_flags & (RELOCATION_GROUP_HAS_ADDEND_FLAG | RELOCATION_GROUPED_BY_ADDEND_FLAG);

          if (group_flags_reloc == RELOCATION_GROUP_HAS_ADDEND_FLAG) {
            /* INFO: Each relocation has an addend. This is the default situation
                       with lld's current encoder. */
          } else if (group_flags_reloc == (RELOCATION_GROUP_HAS_ADDEND_FLAG | RELOCATION_GROUPED_BY_ADDEND_FLAG)) {
            unified_r.r_addend += sleb128_decode(&decoder);
          } else {
            unified_r.r_addend = 0;
          }
        } else {
          if (group_flags & RELOCATION_GROUP_HAS_ADDEND_FLAG)
            LOGF("REL relocations should not have addends, but found one in group %llu", (unsigned long long)i);
        }

        for (size_t i = 0; i < group_size; ++i) {
          if (group_flags & RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG) {
            unified_r.r_offset += group_r_offset_delta;
          } else {
            unified_r.r_offset += sleb128_decode(&decoder);
          }
          if ((group_flags & RELOCATION_GROUPED_BY_INFO_FLAG) == 0) {
            ElfW(Addr) r_info = sleb128_decode(&decoder);
            unified_r.sym_idx = ELF_R_SYM(r_info);
            unified_r.type = ELF_R_TYPE(r_info);

            LOGD("Group %llu: r_info: %llu, sym_idx: %u, type: %u", (unsigned long long)i, (unsigned long long)r_info, unified_r.sym_idx, unified_r.type);
          }

          if (is_rela && group_flags_reloc == RELOCATION_GROUP_HAS_ADDEND_FLAG)
            unified_r.r_addend += sleb128_decode(&decoder);

          _linker_process_unified_relocation(linker, image, &unified_r, load_bias, dynsym, dynstr, is_rela);
        }

        i += group_size;

        LOGD("Processed group %llu: size %llu, flags 0x%llx", (unsigned long long)i, (unsigned long long)group_size, (unsigned long long)group_flags);
      }
    }
  #endif

  /* INFO: Process PLT relocations, if any.

     SOURCES:
       - relocate_linker by AOSP's linker
  */
  if (jmprel) {
    LOGD("Processing %s PLT relocations for %s", pltrel_type == DT_RELA ? "RELA" : "REL", image->elf);

    if (pltrel_type == DT_RELA) {
      for (ElfW(Rela) *r = jmprel; (void *)r < (void *)jmprel + jmprel_sz; r++) {
        LOGD("Processing PLT relocation of type %llu for %s", (unsigned long long)ELF_R_TYPE(r->r_info), image->elf);

        struct _linker_unified_r unified_r = {
          .sym_idx = ELF_R_SYM(r->r_info),
          .type = ELF_R_TYPE(r->r_info),
          .r_offset = r->r_offset,
          .r_addend = pltrel_type == DT_RELA ? r->r_addend : 0
        };

        _linker_process_unified_relocation(linker, image, &unified_r, load_bias, dynsym, dynstr, true);
      }
    } else {
      for (ElfW(Rel) *r = jmprel; (void *)r < (void *)jmprel + jmprel_sz; r++) {
        LOGD("Processing PLT relocation of type %llu for %s", (unsigned long long)ELF_R_TYPE(r->r_info), image->elf);

        struct _linker_unified_r unified_r = {
          .sym_idx = ELF_R_SYM(r->r_info),
          .type = ELF_R_TYPE(r->r_info),
          .r_offset = r->r_offset,
          .r_addend = 0
        };

        _linker_process_unified_relocation(linker, image, &unified_r, load_bias, dynsym, dynstr, false);
      }
    }
  }
}

static bool _linker_is_library_loaded(struct linker *linker, const char *lib_path) {
  if (strcmp(linker->img->elf, lib_path) == 0) return true;

  for (int i = 0; i < linker->dep_count; i++) {
    if (strcmp(linker->dependencies[i].img->elf, lib_path) == 0) return true;
  }

  return false;
}

static void _linker_zero_out_writable_segments(ElfImg *img) {
  ElfW(Phdr) *phdr = (ElfW(Phdr) *)((uintptr_t)img->header + img->header->e_phoff);
  uintptr_t dynamic_vaddr = 0;

  for (int i = 0; i < img->header->e_phnum; i++) {
    if (phdr[i].p_type != PT_DYNAMIC) continue;

    dynamic_vaddr = phdr[i].p_vaddr;

    LOGD("Located PT_DYNAMIC segment at virtual address: 0x%lx", dynamic_vaddr);

    break;
  }

  if (dynamic_vaddr == 0) {
    LOGE("Could not find PT_DYNAMIC segment in '%s'. Aborting cleanup to be safe.", img->elf);

    return;
  }

  LOGD("Scanning for pure data segment to zero out in '%s'.", img->elf);
  for (int i = 0; i < img->header->e_phnum; i++) {
    if (phdr[i].p_type != PT_LOAD) continue;

    /* INFO: Only zero out in writable, non-executable segments. */
    if (!(phdr[i].p_flags & PF_W) || phdr[i].p_flags & PF_X) continue;

    uintptr_t seg_start = phdr[i].p_vaddr;
    uintptr_t seg_end = seg_start + phdr[i].p_memsz;

    /* INFO: Check if dynamic metadata lives inside this segment, if so, skip. */
    if (dynamic_vaddr >= seg_start && dynamic_vaddr < seg_end) {
      LOGD("Skipping segment #%d (vaddr: 0x%lx) because it contains dynamic linking data.", i, seg_start);

      continue;
    }

    void *segment_addr = (void *)((uintptr_t)img->base + phdr[i].p_vaddr - img->bias);
    size_t segment_size = phdr[i].p_memsz;

    if (segment_size > 0) {
      LOGD("Found pure data segment #%d. Zeroing out.", i);
      LOGD(" -> Address: %p, Size: %zu bytes.", segment_addr, segment_size);

      memset(segment_addr, 0, segment_size);
    }
  }
}

static void _linker_restore_protections(ElfImg *image) {
  ElfW(Phdr) *phdr = (ElfW(Phdr) *)((uintptr_t)image->header + image->header->e_phoff);

  /* INFO: Find the minimum and maximum addresses of all loadable segments. */
  uintptr_t min_addr = UINTPTR_MAX;
  uintptr_t max_addr = 0;
  for (int i = 0; i < image->header->e_phnum; i++) {
    if (phdr[i].p_type != PT_LOAD) continue;

    uintptr_t seg_start_addr = (uintptr_t)image->base + phdr[i].p_vaddr - image->bias;
    uintptr_t seg_end_addr = seg_start_addr + phdr[i].p_memsz;

    if (seg_start_addr < min_addr) min_addr = seg_start_addr;
    if (seg_end_addr > max_addr) max_addr = seg_end_addr;
  }

  /* INFO: No loadable segments found, nothing to do. */
  if (min_addr >= max_addr) return; 

  uintptr_t start_page_addr = _page_start(min_addr);
  uintptr_t end_page_addr = _page_end(max_addr);
  size_t num_pages = (end_page_addr - start_page_addr) / system_page_size;

  if (num_pages == 0) return;

  int *page_protections = calloc(num_pages, sizeof(int));
  if (!page_protections) {
    LOGE("Failed to allocate memory for page protection map for %s.", image->elf);

    return;
  }

  for (int i = 0; i < image->header->e_phnum; i++) {
    if (phdr[i].p_type != PT_LOAD) continue;

    int seg_prot = 0;
    if (phdr[i].p_flags & PF_R) seg_prot |= PROT_READ;
    if (phdr[i].p_flags & PF_W) seg_prot |= PROT_WRITE;
    if (phdr[i].p_flags & PF_X) seg_prot |= PROT_EXEC;

    uintptr_t seg_start_addr = (uintptr_t)image->base + phdr[i].p_vaddr - image->bias;
    uintptr_t seg_end_addr = seg_start_addr + phdr[i].p_memsz;
    uintptr_t current_page = _page_start(seg_start_addr);

    while (current_page < _page_end(seg_end_addr)) {
      size_t page_index = (current_page - start_page_addr) / system_page_size;
      if (page_index < num_pages)
        page_protections[page_index] |= seg_prot;
      else
        LOGF("Calculated page index %zu out of bounds (num_pages: %zu) for segment in %s", page_index, num_pages, image->elf);

      current_page += system_page_size;
    }
  }

  /* INFO: Restore protections for all pages in the range. */
  for (size_t i = 0; i < num_pages; i++) {
    uintptr_t current_page = start_page_addr + (i * system_page_size);
    int final_prot = page_protections[i];

    if (final_prot != 0 && mprotect((void *)current_page, system_page_size, final_prot) != 0)
      LOGW("mprotect failed to restore prot %d for page %p in %s: %s", final_prot, (void *)current_page, image->elf, strerror(errno));
    else if (final_prot & PROT_EXEC)
      __builtin___clear_cache((char *)current_page, (char *)current_page + system_page_size);
  }

  free(page_protections);
}

struct relro_region {
  void  *addr;
  size_t size;
};

#define MAX_RELRO 8
struct relro_region relro_regions[MAX_RELRO];
size_t relro_count = 0;

static void verify_exception_tables(ElfImg *img) {
  LOGD("Verifying exception tables for %s", img->elf);
  
  // Check if .gcc_except_table exists and is mapped
  if (img->gcc_except_table && img->gcc_except_table_size > 0) {
    LOGD("  .gcc_except_table: %p (size %zu)", img->gcc_except_table, img->gcc_except_table_size);
    
    // Try to read first byte to verify it's mapped
    volatile uint8_t test = *(const uint8_t*)img->gcc_except_table;
    (void)test;
    LOGD("  .gcc_except_table is readable");
  } else {
    LOGW("  No .gcc_except_table found!");
  }
  
  if (img->eh_frame && img->eh_frame_size > 0) {
    LOGD("  .eh_frame: %p (size %zu)", img->eh_frame, img->eh_frame_size);
  }
  
  if (img->eh_frame_hdr && img->eh_frame_hdr_size > 0) {
    LOGD("  .eh_frame_hdr: %p (size %zu)", img->eh_frame_hdr, img->eh_frame_hdr_size);
  }
}


bool linker_link(struct linker *linker) {
  struct carray *loaded_libs = carray_create(64);
  if (!loaded_libs) {
    LOGE("Failed to create loaded libraries array");

    return false;
  }

  if (linker->img->strtab_start) {
    ElfW(Phdr) *phdr = (ElfW(Phdr) *)((uintptr_t)linker->img->header + linker->img->header->e_phoff);
    ElfW(Dyn) *dyn = NULL;
    for (int i = 0; i < linker->img->header->e_phnum; i++) {
      if (phdr[i].p_type == PT_DYNAMIC) {
        dyn = (ElfW(Dyn) *)((uintptr_t)linker->img->base + phdr[i].p_vaddr - linker->img->bias);
      }

      // if (phdr[i].p_type == PT_GNU_RELRO) {
      //   if (relro_count >= MAX_RELRO) {
      //     LOGE("Reached maximum number of RELRO regions");

      //     carray_destroy(loaded_libs);

      //     return false;
      //   }

      //   relro_regions[relro_count].addr = (void *)((uintptr_t)linker->img->base + phdr[i].p_vaddr - linker->img->bias);
      //   relro_regions[relro_count].size = phdr[i].p_memsz;
      //   relro_count++;

      //   LOGD("Found RELRO segment in main image: %s", linker->img->elf);
      // }
    }

    if (dyn) for (ElfW(Dyn) *d = dyn; d->d_tag != DT_NULL; ++d) {
      if (d->d_tag != DT_NEEDED) continue;

      LOGD("Found needed dependency in main image: %s", (const char *)linker->img->strtab_start + d->d_un.d_val);
      if (!carray_add(loaded_libs, (const char *)linker->img->strtab_start + d->d_un.d_val)) {
        LOGE("Failed to add dependency to loaded libraries array");

        return false;
      }
    }
  }

  for (int i = 0; i < carray_length(loaded_libs); i++) {
    char *lib_name = carray_get(loaded_libs, i);
    if (!lib_name) {
      LOGE("Loaded library name is NULL");

      carray_destroy(loaded_libs);

      return false;
    }

    char lib_full_path[PATH_MAX];
    if (!_linker_find_library_path(lib_name, lib_full_path, sizeof(lib_full_path))) {
      LOGE("Could not find required library: %s", lib_name);

      carray_destroy(loaded_libs);

      return false;
    }

    if (_linker_is_library_loaded(linker, lib_full_path)) {
      LOGD("Library already loaded: %s", lib_full_path);

      continue;
    }

    LOGD("Loading library: %s", lib_full_path);

    struct loaded_dep *current_dep = &linker->dependencies[linker->dep_count];
    void *base_addr = NULL;
    ElfImg *check_img = ElfImg_create(lib_full_path, NULL);
    if (check_img && check_img->base) {
      base_addr = check_img->base;

      ElfImg_destroy(check_img);

      current_dep->img = ElfImg_create(lib_full_path, base_addr);
      current_dep->is_manual_load = false;
    } else {
      base_addr = linker_load_library_manually(lib_full_path, current_dep);
      if (!base_addr) {
        LOGE("Failed to manually load library: %s", lib_full_path);

        carray_destroy(loaded_libs);

        return false;
      }

      current_dep->img = ElfImg_create(lib_full_path, base_addr);

      _linker_zero_out_writable_segments(current_dep->img);
    }

    if (!current_dep->img) {
      LOGE("Failed to create ELF image for: %s", lib_full_path);

      carray_destroy(loaded_libs);

      return false;
    }

    linker->dep_count++;

    if (current_dep->img->strtab_start) {
      ElfW(Phdr) *dep_phdr = (ElfW(Phdr) *)((uintptr_t)current_dep->img->header + current_dep->img->header->e_phoff);
      ElfW(Dyn) *dep_dyn = NULL;

      for (int i = 0; i < current_dep->img->header->e_phnum; i++) {
        if (dep_phdr[i].p_type == PT_DYNAMIC) {
          dep_dyn = (ElfW(Dyn) *)((uintptr_t)current_dep->img->base + dep_phdr[i].p_vaddr - current_dep->img->bias);
        }

      //   if (dep_phdr[i].p_type == PT_GNU_RELRO) {
      //     if (relro_count >= MAX_RELRO) {
      //       LOGE("Reached maximum number of RELRO regions");

      //       carray_destroy(loaded_libs);

      //       return false;
      //     }

      //     relro_regions[relro_count].addr = (void *)((uintptr_t)current_dep->img->base + dep_phdr[i].p_vaddr - current_dep->img->bias);
      //     relro_regions[relro_count].size = dep_phdr[i].p_memsz;
      //     relro_count++;

      //     LOGD("Found RELRO segment in dependency: %s", current_dep->img->elf);
      //   }
      }

      if (dep_dyn) for (ElfW(Dyn) *d = dep_dyn; d->d_tag != DT_NULL; ++d) {
        if (d->d_tag != DT_NEEDED) continue;

        if (carray_exists(loaded_libs, (const char *)current_dep->img->strtab_start + d->d_un.d_val)) {
          LOGD("Dependency already loaded: %s", (const char *)current_dep->img->strtab_start + d->d_un.d_val);

          continue;
        }

        LOGD("Found needed dependency in %s: %s", current_dep->img->elf, (const char *)current_dep->img->strtab_start + d->d_un.d_val);
        if (!carray_add(loaded_libs, (const char *)current_dep->img->strtab_start + d->d_un.d_val)) {
          LOGE("Failed to add dependency to loaded libraries array");

          carray_destroy(loaded_libs);

          return false;
        }
      }
    }
  }

  carray_destroy(loaded_libs);

  LOGD("Registering TLS segments for main library and dependencies.");
  _linker_register_tls_segment(linker->img);
  for (int i = 0; i < linker->dep_count; i++) {
    struct loaded_dep *dep = &linker->dependencies[i];
    if (!dep->is_manual_load) {
      LOGD("Skipping TLS segment registration for pre-existing system library: %s", dep->img->elf);

      continue;
    }

    LOGD("Registering TLS segment for dependency: %s", dep->img->elf);

    _linker_register_tls_segment(dep->img);
  }

  LOGD("Bumping TLS generation for all threads");
  g_tls_generation++;

  LOGD("Making memory writable for relocations");
  ElfW(Phdr) *main_phdr = (ElfW(Phdr) *)((uintptr_t)linker->img->header + linker->img->header->e_phoff);
  for (int j = 0; j < linker->img->header->e_phnum; j++) {
    if (main_phdr[j].p_type != PT_LOAD || (main_phdr[j].p_flags & PF_W)) continue;

    void *page_start = (void *)(((uintptr_t)linker->img->base + main_phdr[j].p_vaddr - linker->img->bias) & ~(system_page_size - 1));
    size_t page_len = (main_phdr[j].p_vaddr + main_phdr[j].p_memsz + system_page_size -1) & ~(system_page_size -1) - (main_phdr[j].p_vaddr & ~(system_page_size-1));

    if (mprotect(page_start, page_len, PROT_READ | PROT_WRITE | (main_phdr[j].p_flags & PF_X ? PROT_EXEC : 0)) != 0)
      LOGW("mprotect failed to make main image segment %d writable: %s", j, strerror(errno));
  }

  for (int i = 0; i < linker->dep_count; i++) {
    struct loaded_dep *dep = &linker->dependencies[i];
    if (!dep->is_manual_load) continue;

    ElfW(Phdr) *dep_phdr = (ElfW(Phdr) *)((uintptr_t)dep->img->header + dep->img->header->e_phoff);
    for (int j = 0; j < dep->img->header->e_phnum; j++) {
      if (dep_phdr[j].p_type != PT_LOAD || (dep_phdr[j].p_flags & PF_W)) continue;

      void *page_start = (void *)(((uintptr_t)dep->img->base + dep_phdr[j].p_vaddr - dep->img->bias) & ~(system_page_size - 1));
      size_t page_len = (dep_phdr[j].p_vaddr + dep_phdr[j].p_memsz + system_page_size -1) & ~(system_page_size -1) - (dep_phdr[j].p_vaddr & ~(system_page_size-1));

      if (mprotect(page_start, page_len, PROT_READ | PROT_WRITE | (dep_phdr[j].p_flags & PF_X ? PROT_EXEC : 0)) != 0)
        LOGW("mprotect failed for make segment %d in %s writable: %s", j, dep->img->elf, strerror(errno));
    }
  }

  LOGD("Processing relocations for main library and dependencies.");
  _linker_process_relocations(linker, linker->img);

  for (int i = 0; i < linker->dep_count; i++) {
    if (!linker->dependencies[i].is_manual_load) {
      LOGD("Skipping relocations for pre-existing system library: %s", linker->dependencies[i].img->elf);

      continue;
    }

    LOGD("Processing relocations for manually loaded dependency: %s", linker->dependencies[i].img->elf);
    _linker_process_relocations(linker, linker->dependencies[i].img);
  }

  // Protect RELRO regions
  // for (size_t i = 0; i < relro_count; i++) {
  //   struct relro_region *region = &relro_regions[i];
  //   if (mprotect(region->addr, region->size, PROT_READ) != 0) {
  //     LOGW("Failed to mprotect RELRO region at %p with size %zu: %s", region->addr, region->size, strerror(errno));
  //   } else {
  //     LOGD("Protected RELRO region at %p with size %zu", region->addr, region->size);
  //   }
  // }

  LOGD("Restoring memory protections after relocations");
  _linker_restore_protections(linker->img);

  for (int i = 0; i < linker->dep_count; i++) {
    struct loaded_dep *dep = &linker->dependencies[i];
    if (!dep->is_manual_load) continue;

    _linker_restore_protections(dep->img);
  }

  // Register main library
  if (!register_custom_library_for_backtrace(linker->img))
    LOGW("Failed to register main library for backtrace support");

  register_eh_frame_for_library(linker->img);
  // Register manually loaded dependencies
  for (int i = 0; i < linker->dep_count; i++) {
    struct loaded_dep *dep = &linker->dependencies[i];
    if (dep->img && dep->is_manual_load) {
        LOGD("Registering dependency %s for backtrace support", dep->img->elf);
        if (!register_custom_library_for_backtrace(dep->img)) {
            LOGW("Failed to register dependency %s for backtrace support", dep->img->elf);
        }
        register_eh_frame_for_library(dep->img);
    }
  }

  _linker_call_preinit_constructors(linker->img);

  /* INFO: Dependencies have their constructors called before the main elf. */
  for (int i = 0; i < linker->dep_count; i++) {
    struct loaded_dep *dep = &linker->dependencies[i];
    if (dep->img && dep->is_manual_load) {
      LOGD("Calling constructors for manually loaded dependency %s", dep->img->elf);
      _linker_call_constructors(dep->img);
    } else if (dep->img) {
      LOGD("Skipping constructor call for pre-loaded dependency %s", dep->img->elf);
    }
  }

  _linker_call_constructors(linker->img);

  verify_exception_tables(linker->img);
  for (int i = 0; i < linker->dep_count; i++) {
    if (linker->dependencies[i].img)
      verify_exception_tables(linker->dependencies[i].img);
  }

  linker->is_linked = true;

  return true;
}
