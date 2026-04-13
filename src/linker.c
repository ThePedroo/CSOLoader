/* Copyright (c) 2025 ThePedroo. All rights reserved.
 *
 * This source code is licensed under the GNU AGPLv3 License found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/auxv.h>
#include <link.h>
#include <limits.h>

#include <sys/prctl.h>
#include <unistd.h>
#include <elf.h>

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

#ifdef __LP64__
  #define PW_SELECT(c32, c64) c64
#else
  #define PW_SELECT(c32, c64) c32
#endif

#ifndef ELF_R_SYM
  #define ELF_R_SYM PW_SELECT(ELF32_R_SYM, ELF64_R_SYM)
#endif

#ifndef ELF_R_TYPE
  #define ELF_R_TYPE PW_SELECT(ELF32_R_TYPE, ELF64_R_TYPE)
#endif

#ifndef ELF_ST_BIND
  #define ELF_ST_BIND PW_SELECT(ELF32_ST_BIND, ELF64_ST_BIND)
#endif

#ifndef ALIGN_UP
  #define ALIGN_UP(x, a)  ( ((x) + ((a) - 1)) & ~((a) - 1) )
#endif

#ifndef ALIGN_DOWN
  #define ALIGN_DOWN(x, a)  ( (x) & ~((a) - 1) )
#endif

static size_t system_page_size;

#define MAX_ACTIVE_LINKERS 16
static struct linker *g_active_linkers[MAX_ACTIVE_LINKERS];
static int g_active_linker_count = 0;

static void _linker_register(struct linker *linker) {
  for (int i = 0; i < g_active_linker_count; i++) {
    if (g_active_linkers[i] == linker) return;
  }

  if (g_active_linker_count >= MAX_ACTIVE_LINKERS) {
    LOGF("Maximum active linker count (%d) exceeded", MAX_ACTIVE_LINKERS);

    return;
  }

  g_active_linkers[g_active_linker_count++] = linker;
}

static void _linker_unregister(struct linker *linker) {
  for (int i = 0; i < g_active_linker_count; i++) {
    if (g_active_linkers[i] != linker) continue;

    g_active_linkers[i] = g_active_linkers[--g_active_linker_count];
    g_active_linkers[g_active_linker_count] = NULL;

    return;
  }
}

#ifdef CSOLOADER_MAKE_LINKER_HOOKS
  static struct linker *_linker_find_by_caller_address(void *caller_addr) {
    uintptr_t addr = (uintptr_t)caller_addr;

    for (int i = 0; i < g_active_linker_count; i++) {
      struct linker *linker = g_active_linkers[i];
      if (!linker || !linker->img) continue;

      uintptr_t main_base = (uintptr_t)linker->img->base;
      if (addr >= main_base && addr < main_base + linker->main_map_size)
        return linker;

      for (int j = 0; j < linker->dep_count; j++) {
        struct loaded_dep *dep = &linker->dependencies[j];
        if (!dep->img || !dep->is_manual_load || dep->map_size == 0) continue;

        uintptr_t dep_base = (uintptr_t)dep->img->base;
        if (addr >= dep_base && addr < dep_base + dep->map_size)
          return linker;
      }
    }

    return NULL;
  }
#endif /* CSOLOADER_MAKE_LINKER_HOOKS */

static inline uintptr_t _page_start(uintptr_t addr) {
  return ALIGN_DOWN(addr, system_page_size);
}

static inline uintptr_t _page_end(uintptr_t addr) {
  return ALIGN_DOWN(addr + system_page_size - 1, system_page_size);
}

#ifdef __LP64__
  /* INFO: Pick the start of the highest parsed 4GiB+ gap so the mapping stays
             high and leaves more free space above it, where the process is more
             likely to create VMAs later. */
  static void *_linker_find_highest_gap_start(size_t needed_size) {
    FILE *fp = fopen("/proc/self/maps", "re");
    if (!fp) return NULL;

    needed_size = _page_end(needed_size);

    char *line = NULL;
    size_t line_cap = 0;
    uintptr_t prev_end = 0;
    uintptr_t hint = 0;

    while (getline(&line, &line_cap, fp) != -1) {
      uintptr_t start = 0;
      uintptr_t end = 0;
      if (sscanf(line, "%" PRIxPTR "-%" PRIxPTR, &start, &end) != 2) continue;

      uintptr_t gap_start = _page_end(prev_end ? prev_end : 0x100000000ULL);
      if (start > gap_start && needed_size <= start - gap_start) hint = gap_start;
      if (end > prev_end) prev_end = end;
    }

    free(line);
    fclose(fp);

    return (void *)hint;
  }
#endif

/* INFO: Internal functions START */

int g_argc = 0;
char **g_argv = NULL;
char **g_envp = NULL;

#if 0
/* INFO: preinit only is for the main EXECUTABLE. We don't deal with those, not for now, as
             we are not a system linker that needs to start off everything. */
static void _linker_call_preinit_constructors(struct csoloader_elf *img) {
  if (!img->preinit_array) return;

  LOGD("Calling .preinit_array constructors for %s", img->elf);
  for (size_t i = 0; i < img->preinit_array_count; ++i) {
    LOGD("Calling preinit_array[%zu] at %p", i, img->preinit_array[i]);

    img->preinit_array[i](g_argc, g_argv, g_envp);
  }
}
#endif

static void _linker_call_constructors(struct csoloader_elf *img) {
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

static void _linker_call_destructors(struct csoloader_elf *img) {
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

static const char *_path_basename(const char *path) {
  if (!path) return "";

  const char *slash = strrchr(path, '/');
  return slash ? slash + 1 : path;
}

static int _linker_find_dep_index(struct linker *linker, const char *soname) {
  if (!linker || !soname) return -1;

  for (int i = 0; i < linker->dep_count; i++) {
    struct loaded_dep *dep = &linker->dependencies[i];
    if (dep->img && dep->is_manual_load && strcmp(_path_basename(dep->img->elf), soname) == 0) return i;
  }

  return -1;
}
static bool _linker_call_manual_constructors(struct linker *linker, int index, unsigned char *constructor_state) {
  struct loaded_dep *dep = &linker->dependencies[index];
  if (!dep->img || !dep->is_manual_load) return true;
  if (constructor_state[index]) return constructor_state[index] == 2;

  constructor_state[index] = 1;

  if (dep->img->strtab_start) {
    ElfW(Phdr) *phdr = (ElfW(Phdr) *)((uintptr_t)dep->img->header + dep->img->header->e_phoff);
    ElfW(Dyn) *dyn = NULL;

    for (int i = 0; i < dep->img->header->e_phnum; i++) {
      if (phdr[i].p_type != PT_DYNAMIC) continue;

      dyn = (ElfW(Dyn) *)((uintptr_t)dep->img->base + phdr[i].p_vaddr - dep->img->bias);
      break;
    }

    for (ElfW(Dyn) *d = dyn; dyn && d->d_tag != DT_NULL; ++d) {
      if (d->d_tag != DT_NEEDED) continue;

      const char *dep_name = (const char *)dep->img->strtab_start + d->d_un.d_val;
      if (!dep_name || dep_name[0] == '\0' || strcmp(dep_name, "ld-android.so") == 0) continue;

      int dep_idx = _linker_find_dep_index(linker, dep_name);
      if (dep_idx < 0) continue;

      if (!_linker_call_manual_constructors(linker, dep_idx, constructor_state))
        return false;
    }
  }

  _linker_call_constructors(dep->img);
  constructor_state[index] = 2;

  return true;
}

static int _linker_protect_gnu_relro(struct csoloader_elf *img) {
  ElfW(Phdr) *phdr = (ElfW(Phdr) *)((uintptr_t)img->header + img->header->e_phoff);
  ElfW(Addr) load_bias = (ElfW(Addr))img->base - img->bias;

  for (int i = 0; i < img->header->e_phnum; i++) {
    if (phdr[i].p_type != PT_GNU_RELRO) continue;

    /* AOSP comment: Tricky: what happens when the relro segment does not start
                       or end at page boundaries? We're going to be over-protective
                       here and put every page touched by the segment as read-only. */
    ElfW(Addr) seg_page_start = _page_start(phdr[i].p_vaddr + load_bias);
    ElfW(Addr) seg_page_end = _page_end(phdr[i].p_vaddr + phdr[i].p_memsz + load_bias);
    size_t seg_size = seg_page_end - seg_page_start;

    if (seg_size == 0) continue;

    int ret = mprotect((void *)seg_page_start, seg_size, PROT_READ);
    if (ret < 0) {
      LOGW("Failed to mprotect GNU_RELRO at %p (size %zu) in %s: %s", (void *)seg_page_start, seg_size, img->elf, strerror(errno));

      return -1;
    }

    LOGD("Protected GNU_RELRO region at %p (size %zu) in %s", (void *)seg_page_start, seg_size, img->elf);
  }

  return 0;
}

static void _linker_internal_init() {
  if (system_page_size != 0) return;

  /* INFO: If sysconf returns -1, will cause an integer underflow as the variable is to size_t.
             To fix that, we first assign to a long variable, and only after checked, to size_t. */
  long new_system_page_size = sysconf(_SC_PAGESIZE);
  if (new_system_page_size <= 0) LOGF("Failed to get system page size");

  system_page_size = (size_t)new_system_page_size;

  LOGD("System page size: %zu bytes", system_page_size);
}

static bool _linker_find_library_path(const char *lib_name, char *full_path, size_t full_path_size) {
  const char *search_paths[] = {
    #ifdef __LP64__
      #ifdef __ANDROID__
        "/apex/com.android.tethering/lib64/",
        "/apex/com.android.runtime/lib64/bionic/",
        "/apex/com.android.runtime/lib64/",
        "/apex/com.android.os.statsd/lib64/",
        "/apex/com.android.i18n/lib64/",
        "/apex/com.android.art/lib64/",
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
        "/apex/com.android.tethering/lib/",
        "/apex/com.android.runtime/lib/bionic/",
        "/apex/com.android.runtime/lib/",
        "/apex/com.android.os.statsd/lib/",
        "/apex/com.android.i18n/lib/",
        "/apex/com.android.art/lib/",
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

  /* TODO: Read ldconfig */

  for (int i = 0; search_paths[i] != NULL; ++i) {
    snprintf(full_path, full_path_size, "%s%s", search_paths[i], lib_name);

    if (access(full_path, F_OK) == 0) return true;
  }

  LOGE("Could not find library which shared library depends on: %s", lib_name);
  full_path[0] = '\0';

  return false;
}

#ifdef CSOLOADER_MAKE_LINKER_HOOKS
  static struct csoloader_elf *_linker_find_loaded_image(struct linker *linker, const char *name) {
    const char *base_name = _path_basename(name);
    if (linker->img && (strcmp(linker->img->elf, name) == 0 || strcmp(_path_basename(linker->img->elf), base_name) == 0))
      return linker->img;

    for (int i = 0; i < linker->dep_count; i++) {
      struct loaded_dep *dep = &linker->dependencies[i];
      if (!dep->img || !dep->is_manual_load) continue;

      if (strcmp(dep->img->elf, name) == 0 || strcmp(_path_basename(dep->img->elf), base_name) == 0)
        return dep->img;
    }

    return NULL;
  }

  static struct csoloader_elf *_linker_image_from_handle(struct linker *linker, void *handle) {
    if (!linker || !handle || handle == RTLD_DEFAULT || handle == RTLD_NEXT) return NULL;
    if (handle == linker->img) return linker->img;

    for (int i = 0; i < linker->dep_count; i++) {
      if (!linker->dependencies[i].is_manual_load || handle != linker->dependencies[i].img) continue;

      return linker->dependencies[i].img;
    }

    return NULL;
  }

  static void *_linker_get_original_libdl_symbol(const char *name) {
    struct csoloader_elf *libdl_elf = csoloader_elf_create("libdl.so", NULL);
    if (!libdl_elf) return NULL;

    void *sym = (void *)csoloader_elf_symb_address(libdl_elf, name);
    csoloader_elf_destroy(libdl_elf);

    return sym;
  }

  static void *custom_dlopen(const char *filename, int flags) {
    void *(*original_dlopen)(const char *, int) = (void *(*)(const char *, int))_linker_get_original_libdl_symbol("dlopen");
    if (!filename) return original_dlopen ? original_dlopen(filename, flags) : NULL;

    struct linker *linker = _linker_find_by_caller_address(__builtin_return_address(0));
    if (linker) {
      struct csoloader_elf *img = _linker_find_loaded_image(linker, filename);    
      if (img) return img;
    }

    return original_dlopen ? original_dlopen(filename, flags) : NULL;
  }

  /* INFO: If a handle is shared between modules, this will not be able to find it.*/
  static void *custom_dlsym(void *handle, const char *symbol) {
    void *(*original_dlsym)(void *, const char *) = (void *(*)(void *, const char *))_linker_get_original_libdl_symbol("dlsym");

    struct linker *linker = _linker_find_by_caller_address(__builtin_return_address(0));
    struct csoloader_elf *img = _linker_image_from_handle(linker, handle);
    if (img) {
      if (!symbol) return NULL;

      void *sym = (void *)csoloader_elf_symb_address_exported(img, symbol);
      if (!sym)
        sym = (void *)csoloader_elf_symb_address(img, symbol);

      return sym;
    }

    return original_dlsym ? original_dlsym(handle, symbol) : NULL;
  }

  /* INFO: If a handle is shared between modules, this will not be able to find it.*/
  static int custom_dlclose(void *handle) {
    int (*original_dlclose)(void *) = (int (*)(void *))_linker_get_original_libdl_symbol("dlclose");

    struct linker *linker = _linker_find_by_caller_address(__builtin_return_address(0));
    if (linker && _linker_image_from_handle(linker, handle)) return 0;

    return original_dlclose ? original_dlclose(handle) : -1;
  }
#endif /* CSOLOADER_MAKE_LINKER_HOOKS */

/* INFO: Internal functions END */

bool linker_init(struct linker *linker, struct csoloader_elf *img) {
  _linker_internal_init();

  linker->img = img;
  linker->is_linked = false;
  linker->main_map_size = 0;
  linker->dep_count = 0;
  memset(&linker->tls_indices, 0, sizeof(linker->tls_indices));

  memset(linker->dependencies, 0, sizeof(linker->dependencies));

  _linker_register(linker);

  return true;
}

static void _linker_unregister_tls_segment(struct loaded_dep *dep);

static void _linker_run_dependency_destructors(struct loaded_dep *dep) {
  if (!dep->img || !dep->is_manual_load) return;

  _linker_call_destructors(dep->img);
  unregister_eh_frame_for_library(dep->img);
  unregister_custom_library_for_backtrace(dep->img);
}

static void _linker_release_dependency(struct linker *linker, int index, bool unload) {
  struct loaded_dep *dep = &linker->dependencies[index];
  if (!dep->img) return;

  void *dep_base = dep->img->base;
  size_t dep_map_size = dep->map_size;

  _linker_unregister_tls_segment(dep);
  csoloader_elf_destroy(dep->img);
  dep->img = NULL;
  dep->map_size = 0;

  if (unload && dep->is_manual_load && dep_map_size > 0)
    munmap(dep_base, dep_map_size);
}

static void _linker_release_dependencies(struct linker *linker, bool unload, bool run_destructors) {
  if (run_destructors) {
    for (int i = 0; i < linker->dep_count; i++) {
      _linker_run_dependency_destructors(&linker->dependencies[i]);
    }
  }

  for (int i = linker->dep_count - 1; i >= 0; --i)
    _linker_release_dependency(linker, i, unload);
}

void linker_destroy(struct linker *linker) {
  void *main_base = linker->img->base;
  size_t main_map_size = linker->main_map_size;

  if (linker->is_linked) {
    _linker_call_destructors(linker->img);
    unregister_eh_frame_for_library(linker->img);
    unregister_custom_library_for_backtrace(linker->img);
  }
  
  _linker_release_dependencies(linker, true, linker->is_linked);

  _linker_unregister(linker);

  _linker_unregister_tls_segment((struct loaded_dep *)linker);
  csoloader_elf_destroy(linker->img);
  linker->img = NULL;

  if (main_base && main_map_size > 0)
    munmap(main_base, main_map_size);

  linker->dep_count = 0;
  linker->is_linked = false;
  linker->main_map_size = 0;
}

/* INFO: Free resources related to the library without unloading it */
void linker_abandon(struct linker *linker) {
  _linker_release_dependencies(linker, false, false);

  if (linker->img && linker->is_linked) {
    unregister_eh_frame_for_library(linker->img);
    unregister_custom_library_for_backtrace(linker->img);
  }

  _linker_unregister(linker);

  _linker_unregister_tls_segment((struct loaded_dep *)linker);
  csoloader_elf_destroy(linker->img);
  linker->img = NULL;

  linker->dep_count = 0;
  linker->is_linked = false;
  linker->main_map_size = 0;
}

static size_t phdr_get_load_size(const ElfW(Phdr) *phdr, size_t length, ElfW(Addr) *min_vaddr) {
  ElfW(Addr) lo = UINTPTR_MAX, hi = 0;
  for (size_t i = 0; i < length; ++i) {
    if (phdr[i].p_type != PT_LOAD) continue;

    if (phdr[i].p_vaddr < lo) lo = phdr[i].p_vaddr;
    if (phdr[i].p_vaddr + phdr[i].p_memsz > hi) hi = phdr[i].p_vaddr + phdr[i].p_memsz;
  }

  lo = _page_start(lo);
  hi = _page_end(hi);

  if (min_vaddr) *min_vaddr = lo;

  return hi - lo;
}

static int _linker_load_one_segment(int fd, ElfW(Phdr) *phdr, ElfW(Addr) bias, off_t file_off) {
  ElfW(Addr) seg_start = phdr->p_vaddr + bias;
  ElfW(Addr) seg_end = seg_start + phdr->p_memsz;
  ElfW(Addr) file_end = seg_start + phdr->p_filesz;

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

    /* INFO: Clear the memory to avoid use of unitialized variables and garbage data. This is needed. */
    memset(bss_addr, 0, bss_size);
  }

  /* INFO: This is needed to avoid access to uninitialized data */
  if ((phdr->p_flags & PF_W) && file_end < (seg_start + phdr->p_memsz)) {
    size_t zero_len = _page_end(file_end) - file_end;
    size_t seg_tail = seg_start + phdr->p_memsz - file_end;
    if (zero_len > seg_tail) zero_len = seg_tail;
  
    memset((void *)file_end, 0, zero_len);
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
  out->map_size = phdr_get_load_size(phdr, eh.e_phnum, &min_vaddr);
  if (out->map_size == 0) {
    LOGE("No loadable segments found in ELF headers");

    close(fd);

    free(phdr);

    return NULL;
  }

  #ifdef __LP64__
    void *hint = _linker_find_highest_gap_start(out->map_size);
    if (!hint) {
      LOGE("Failed to find high mmap hint for %s", lib_path);

      close(fd);

      free(phdr);

      return NULL;
    }

    void *base = mmap(hint, out->map_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  #else
    void *base = mmap(NULL, out->map_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  #endif
  if (base == MAP_FAILED) {
    #ifdef __LP64__
      LOGE("Failed to reserve address space at hint %p for %s: %s", hint, lib_path, strerror(errno));
    #else
      LOGE("Failed to reserve address space for %s: %s", lib_path, strerror(errno));
    #endif

    close(fd);

    free(phdr);

    return NULL;
  }

  LOGD("Allocated address space for SO loading at %p (size %zu): %s", base, out->map_size, lib_path);

  ElfW(Addr) bias = (ElfW(Addr))base - min_vaddr;

  /* INFO: Load all segments to the reserved address space */
  for (int i = 0; i < eh.e_phnum; i++) {
    if (phdr[i].p_type != PT_LOAD) continue;

    if (_linker_load_one_segment(fd, &phdr[i], bias, 0) != 0) {
      LOGE("Failed to load segment %d of %s", i, lib_path);

      munmap(base, out->map_size);
      close(fd);

      free(phdr);

      return NULL;
    }
  }

  close(fd);

  out->is_manual_load = true;
  out->load_bias = bias;

  free(phdr);

  return base;
}

struct linker_symbol_info {
  void *addr;
  struct csoloader_elf *img;
  struct tls_indices_data *tls_indices;
};

static struct linker_symbol_info _linker_find_symbol_in_linker_scope(struct linker *linker, struct csoloader_elf *requester, const char *sym_name) {
  if (requester) {
    void *addr = (void *)csoloader_elf_symb_address(requester, sym_name);
    if (addr) {
      if (requester == linker->img) {
        LOGD("Found symbol '%s' in main image: %s via Elf Utils: %p", sym_name, requester->elf, addr);

        return (struct linker_symbol_info) {
          .addr = addr,
          .img = linker->img,
          .tls_indices = &linker->tls_indices
        };
      }

      for (int i = 0; i < linker->dep_count; i++) {
        if (linker->dependencies[i].img != requester) continue;

        LOGD("Found symbol '%s' in requester dependency %d: %s via Elf Utils: %p", sym_name, i, requester->elf, addr);

        return (struct linker_symbol_info) {
          .addr = addr,
          .img = requester,
          .tls_indices = &linker->dependencies[i].tls_indices
        };
      }
    }
  }

  if (linker->img != requester) {
    void *addr = (void *)csoloader_elf_symb_address_exported(linker->img, sym_name);
    if (addr) {
      LOGD("Found exported symbol '%s' in main image: %s via Elf Utils: %p", sym_name, linker->img->elf, addr);

      return (struct linker_symbol_info) {
        .addr = addr,
        .img = linker->img,
        .tls_indices = &linker->tls_indices
      };
    }
  }

  for (int i = 0; i < linker->dep_count; i++) {
    struct loaded_dep *candidate = &linker->dependencies[i];
    if (!candidate->img || candidate->img == requester) continue;

    void *addr = (void *)csoloader_elf_symb_address_exported(candidate->img, sym_name);
    if (!addr) continue;

    LOGD("Found exported symbol '%s' in dependency %d: %s via Elf Utils: %p", sym_name, i, candidate->img->elf, addr);

    return (struct linker_symbol_info) {
      .addr = addr,
      .img = candidate->img,
      .tls_indices = &candidate->tls_indices
    };
  }

  LOGE("Symbol '%s' not found in any loaded image", sym_name);

  return (struct linker_symbol_info) {
    .addr = NULL,
    .img = NULL,
    .tls_indices = NULL
  };
}

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
static ElfW(Addr) handle_indirect_symbol(uintptr_t resolver_addr) {
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
  /* INFO: Initial TLS data to copy from .tdata */
  const void *init_image;
  struct csoloader_elf *owner;
};

struct thread_tls {
  /* INFO: When this was last synced with global generation */
  size_t generation;
  /* INFO: Per-module TLS block pointers */
  void *modules[MAX_TLS_MODULES];
};

static struct tls_module g_tls_modules[MAX_TLS_MODULES];
static size_t g_tls_generation = 0;
static pthread_mutex_t g_tls_mutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_key_t g_tls_key;
static bool g_tls_key_initialized = false;
static pthread_once_t g_tls_key_once = PTHREAD_ONCE_INIT;

/* INFO: This structure is used to access thread-local storage (TLS) variables. 
           It cannot and should not have its members modified. */
struct tls_index {
  unsigned long module;
  unsigned long offset;
};

static void _linker_destroy_thread_tls(void *arg) {
  struct thread_tls *ttls = (struct thread_tls *)arg;
  if (!ttls) return;

  for (size_t i = 1; i < MAX_TLS_MODULES; i++) {
    if (!ttls->modules[i]) continue;

    free(ttls->modules[i]);
    ttls->modules[i] = NULL;
  }

  free(ttls);
}

static void _linker_alloc_tls_key_once(void) {
  pthread_key_create(&g_tls_key, _linker_destroy_thread_tls);
}

static void *_linker_allocate_module_tls(struct tls_module *mod) {
  if (!mod || mod->module_id == 0 || mod->memsz == 0) return NULL;

  size_t align = mod->align;
  /* INFO: posix_memalign requires alignment >= sizeof(void *) and power of 2 */
  if (align < sizeof(void *)) align = sizeof(void *);
  if (system_page_size > 0 && align > system_page_size) align = system_page_size;

  void *block = NULL;
  if (posix_memalign(&block, align, mod->memsz) != 0) {
    LOGE("Failed to allocate TLS block for module %zu: size=%zu, align=%zu", mod->module_id, mod->memsz, align);

    return NULL;
  }

  /* INFO: Zero the block first (.tbss), then copy initialized data (.tdata) */
  memset(block, 0, mod->memsz);
  if (mod->init_image && mod->filesz > 0)
    memcpy(block, mod->init_image, mod->filesz);

  return block;
}

static struct thread_tls *_linker_get_thread_tls(void) {
  pthread_once(&g_tls_key_once, _linker_alloc_tls_key_once);
  g_tls_key_initialized = true;

  struct thread_tls *ttls = (struct thread_tls *)pthread_getspecific(g_tls_key);
  if (!ttls) {
    ttls = (struct thread_tls *)calloc(1, sizeof(struct thread_tls));
    if (!ttls) {
      LOGE("Failed to allocate thread TLS state");

      return NULL;
    }

    ttls->generation = 0;

    pthread_setspecific(g_tls_key, ttls);
  }

  return ttls;
}

static void _linker_sync_thread_tls(struct thread_tls *ttls) {
  pthread_mutex_lock(&g_tls_mutex);
  size_t current_gen = g_tls_generation;
  pthread_mutex_unlock(&g_tls_mutex);

  if (ttls->generation >= current_gen) return;

  for (size_t i = 1; i < MAX_TLS_MODULES; i++) {
    struct tls_module *mod = &g_tls_modules[i];
    if (mod->module_id != 0 || !ttls->modules[i]) continue;

    free(ttls->modules[i]);
    ttls->modules[i] = NULL;
  }

  ttls->generation = current_gen;
}

static bool _linker_register_tls_segment(struct csoloader_elf *img) {
  if (!img->tls_segment) return true;

  pthread_mutex_lock(&g_tls_mutex);

  size_t mod_id;
  for (mod_id = 1; mod_id < MAX_TLS_MODULES; mod_id++) {
    if (g_tls_modules[mod_id].module_id == 0) break;
  }

  if (mod_id == MAX_TLS_MODULES) {
    LOGE("TLS module overflow: max %d modules reached", MAX_TLS_MODULES);

    pthread_mutex_unlock(&g_tls_mutex);

    return false;
  }

  struct tls_module *mod = &g_tls_modules[mod_id];
  mod->module_id  = mod_id;
  mod->align      = img->tls_segment->p_align ? img->tls_segment->p_align : 1;
  mod->memsz      = img->tls_segment->p_memsz;
  mod->filesz     = img->tls_segment->p_filesz;
  mod->init_image = (const void *)((uintptr_t)img->base + img->tls_segment->p_vaddr - img->bias);
  mod->owner      = img;

  img->tls_mod_id = mod_id;
  g_tls_generation++;

  LOGD("Registered TLS module %zu for %s: memsz=%zu, filesz=%zu, align=%zu", mod_id, img->elf, mod->memsz, mod->filesz, mod->align);

  pthread_mutex_unlock(&g_tls_mutex);

  return true;
}

static void _linker_unregister_tls_segment(struct loaded_dep *dep) {
  if (!dep->img || dep->img->tls_mod_id == 0) return;

  pthread_mutex_lock(&g_tls_mutex);

  size_t mod_id = dep->img->tls_mod_id;
  if (mod_id < MAX_TLS_MODULES && g_tls_modules[mod_id].owner == dep->img) {
    LOGD("Unregistering TLS module %zu for %s", mod_id, dep->img->elf);

    memset(&g_tls_modules[mod_id], 0, sizeof(struct tls_module));
    dep->img->tls_mod_id = 0;

    g_tls_generation++;
  }

  pthread_mutex_unlock(&g_tls_mutex);
  
  /* INFO: Free all tracked tls_index structures */
  if (dep->tls_indices.count != 0) {
    for (size_t i = 0; i < dep->tls_indices.count; i++) {
      free(dep->tls_indices.indices[i]);
    }
    
    free(dep->tls_indices.indices);
    dep->tls_indices.indices = NULL;
    dep->tls_indices.count = 0;
    dep->tls_indices.capacity = 0;
  }
}

static bool _track_tls_index(struct tls_indices_data *tls_indices, struct tls_index *ti) {
  if (!tls_indices || !ti) return false;

  if (tls_indices->count >= tls_indices->capacity) {
    size_t new_cap = tls_indices->capacity == 0 ? 8 : tls_indices->capacity * 2;
    void **new_arr = realloc(tls_indices->indices, new_cap * sizeof(void *));
    if (!new_arr) {
      LOGE("Failed to grow tls_indices array");

      return false;
    }

    tls_indices->indices = new_arr;
    tls_indices->capacity = new_cap;
  }

  tls_indices->indices[tls_indices->count++] = ti;

  return true;
}

static struct tls_index *allocate_tls_index_for_symbol(struct csoloader_elf *img, struct tls_indices_data *tls_indices, ElfW(Sym) *dynsym, uint32_t sym_idx, ElfW(Addr) addend) {
  struct tls_index *ti = malloc(sizeof(*ti));
  if (!ti) {
    LOGE("Failed to allocate memory for tls_index");

    return NULL;
  }

  ti->module = img->tls_mod_id;

  ElfW(Sym) *sym = &dynsym[sym_idx];
  ti->offset = sym->st_value + addend;

  if (!_track_tls_index(tls_indices, ti)) {
    LOGW("Failed to track tls_index for cleanup - potential memory leak");
  }

  return ti;
}

void *__tls_get_addr(struct tls_index *ti) {
  LOGD("__tls_get_addr called: ti=%p, module=%zu, offset=%zu", ti, (size_t)ti->module, (size_t)ti->offset);

  size_t mod_id = ti->module;

  if (mod_id == 0 || mod_id >= MAX_TLS_MODULES) {
    LOGE("Library tried to access invalid TLS module ID %zu", mod_id);

    return NULL;
  }

  pthread_mutex_lock(&g_tls_mutex);

  struct tls_module *mod = &g_tls_modules[mod_id];
  if (mod->module_id == 0) {
    pthread_mutex_unlock(&g_tls_mutex);

    LOGE("Library tried to access unregistered TLS module %zu", mod_id);

    return NULL;
  }

  pthread_mutex_unlock(&g_tls_mutex);

  struct thread_tls *ttls = _linker_get_thread_tls();
  if (!ttls) {
    LOGE("Library tried to access TLS, but thread TLS allocation failed");

    return NULL;
  }

  _linker_sync_thread_tls(ttls);

  pthread_mutex_lock(&g_tls_mutex);

  if (!ttls->modules[mod_id]) {
    ttls->modules[mod_id] = _linker_allocate_module_tls(mod);
    if (!ttls->modules[mod_id]) {
      pthread_mutex_unlock(&g_tls_mutex);

      LOGE("Failed to allocate TLS block for module %zu on thread %llu", mod_id, (unsigned long long)pthread_self());

      return NULL;
    }
  }

  pthread_mutex_unlock(&g_tls_mutex);

  return (uint8_t *)ttls->modules[mod_id] + ti->offset;
}

static inline ElfW(Addr) _linker_get_tpidr(void) {
  #if defined(__aarch64__)
    /* INFO: ARM64 uses the TPIDR_EL0 register to store the thread pointer */
    ElfW(Addr) tpidr;
    __asm__ volatile("mrs %0, tpidr_el0" : "=r"(tpidr));

    return tpidr;
  #elif defined(__arm__)
    /* INFO: ARM32 uses a different method, CP15 register */
    ElfW(Addr) tpidr;
    __asm__ volatile("mrc p15, 0, %0, c13, c0, 3" : "=r"(tpidr));

    return tpidr;
  #elif defined(__i386__) || defined(__x86_64__)
    /* INFO: x86 uses segment registers, but TLSDESC is not used on x86 */

    return 0;
  #else
    return 0;
  #endif
}

struct _linker_unified_r {
  uint32_t sym_idx;
  uint32_t type;
  ElfW(Addr) r_offset;
  ElfW(Addr) r_addend;
};

static ElfW(Addr) dynamic_tls_resolver(ElfW(Addr) *desc) {
  /* INFO: desc[0] = resolver (this function), desc[1] = our tls_index pointer */
  struct tls_index *ti = (struct tls_index *)desc[1];

  void *addr = __tls_get_addr(ti);
  if (!addr) {
    LOGE("dynamic_tls_resolver: __tls_get_addr failed for module=%zu, offset=%zu", (size_t)ti->module, (size_t)ti->offset);

    return 0;
  }

  /* INFO: Calculate offset from tpidr_el0 so that caller computes the final TLS address. */
  ElfW(Addr) tpidr = _linker_get_tpidr();
  ElfW(Addr) result = (ElfW(Addr))addr - tpidr;

  LOGD("Dynamically resolved tls_index: desc=%p, ti=%p, module=%zu, offset=%zu, addr=%p, tpidr=0x%lx, returning=0x%lx", desc, ti, (size_t)ti->module, (size_t)ti->offset, addr, (unsigned long)tpidr, (unsigned long)result);

  return result;
}

static ElfW(Addr) tlsdesc_resolver_unresolved_weak(ElfW(Addr) *desc) {
  ElfW(Addr) addend = desc[1];
  ElfW(Addr) tpidr = _linker_get_tpidr();
  ElfW(Addr) result = addend - tpidr;

  LOGD("Resolver for unresolved weak: addend=%zu, tpidr=0x%lx, returning=0x%lx", (size_t)addend, (unsigned long)tpidr, (unsigned long)result);

  return result;
}

static bool _linker_process_unified_relocation(struct linker *linker, struct loaded_dep *dep, struct _linker_unified_r *r, ElfW(Addr) load_bias, ElfW(Sym) *dynsym, char *dynstr, bool is_rela) {
  ElfW(Addr) *target_addr = (ElfW(Addr) *)(load_bias + r->r_offset);

  switch (r->type) {
    case R_GENERIC_NONE: {
      LOGD("Skipping R_GENERIC_NONE relocation at %p in %s", target_addr, dep->img->elf);

      break;
    }
    case R_GENERIC_COPY: {
      LOGW("R_GENERIC_COPY relocation at %p in %s: This relocation type is not supported yet", target_addr, dep->img->elf);

      break;
    }
    case R_GENERIC_IRELATIVE: {
      *target_addr = handle_indirect_symbol(load_bias + (is_rela ? r->r_addend : *(ElfW(Addr) *)(target_addr)));

      LOGD("R_GENERIC_IRELATIVE relocation at %p in %s: Resolved to %p", target_addr, dep->img->elf, (void *)*target_addr);

      break;
    }
    case R_GENERIC_RELATIVE: {
      *target_addr = load_bias + (is_rela ? r->r_addend : *(ElfW(Addr) *)(target_addr));

      LOGD("R_GENERIC_RELATIVE relocation at %p in %s: Resolved to %p", target_addr, dep->img->elf, (void *)*target_addr);

      break;
    }
    case R_GENERIC_GLOB_DAT:
    case R_GENERIC_ABSOLUTE:
    case R_GENERIC_JUMP_SLOT:
    #ifdef __x86_64__
      case R_X86_64_32:
      case R_X86_64_PC32:
    #elif defined(__i386__)
      case R_386_PC32:
    #endif
    {
      ElfW(Sym) *sym_ent = &dynsym[r->sym_idx];
      const char *sym_name = dynstr + sym_ent->st_name;
      uint8_t sym_bind = ELF_ST_BIND(sym_ent->st_info);
      struct linker_symbol_info sym = _linker_find_symbol_in_linker_scope(linker, dep->img, sym_name);
      if (!sym.addr) {
        if (sym_bind == STB_WEAK) {
          ElfW(Addr) weak_value = 0;
          if (r->type == R_GENERIC_ABSOLUTE) weak_value = is_rela ? r->r_addend : *(ElfW(Addr) *)target_addr;
          else if (is_rela) weak_value = r->r_addend;

          *target_addr = weak_value;

          LOGD("Weak symbol '%s' unresolved in %s, using fallback value %p", sym_name, dep->img->elf, (void *)weak_value);

          return true;
        }

        LOGE("Symbol '%s' not found for relocation in %s", sym_name, dep->img->elf);

        return false;
      }

      /* INFO: If CSOLoader is unloaded, or for whatever reason, isn't in the same memory location, and a
                 library loaded by it calls any of those functions (with the macro defined), it will try
                 to call an address that is no longer valid, resulting in an undefined behavior, which
                 most of the time, in most devices, will result in a segmentation fault. */
      #ifdef CSOLOADER_MAKE_LINKER_HOOKS
        if (strcmp(sym_name, "dl_iterate_phdr") == 0) {
          LOGD("Special case for dl_iterate_phdr: using custom implementation");

          *target_addr = (ElfW(Addr))custom_dl_iterate_phdr;

          return true;
        }

        if (strcmp(sym_name, "dladdr") == 0) {
          LOGD("Special case for dladdr: using custom implementation");

          *target_addr = (ElfW(Addr))custom_dladdr;

          return true;
        }

        if (strcmp(sym_name, "dlopen") == 0) {
          LOGD("Special case for dlopen: using custom implementation");

          *target_addr = (ElfW(Addr))custom_dlopen;

          return true;
        }

        if (strcmp(sym_name, "dlsym") == 0) {
          LOGD("Special case for dlsym: using custom implementation");

          *target_addr = (ElfW(Addr))custom_dlsym;

          return true;
        }

        if (strcmp(sym_name, "dlclose") == 0) {
          LOGD("Special case for dlclose: using custom implementation");

          *target_addr = (ElfW(Addr))custom_dlclose;

          return true;
        }
      #endif /* CSOLOADER_MAKE_LINKER_HOOKS */

      /* INFO: While the comment for other hooks is still valid for this one, it is a critical
                 component of the TLS system from CSOLoader, and if not hooked, will also result
                 in improper TLS handling. So, because of that, it will always be hooked,
                 regardless of the CSOLOADER_MAKE_LINKER_HOOKS macro. */
      if (strcmp(sym_name, "__tls_get_addr") == 0) {
        LOGD("Special case for __tls_get_addr: using custom TLS implementation");

        *target_addr = (ElfW(Addr))__tls_get_addr;

        return true;
      }

      switch (r->type) {
        case R_GENERIC_GLOB_DAT:
        case R_GENERIC_JUMP_SLOT: {
          ElfW(Addr) addend = is_rela ? r->r_addend : 0;
          *target_addr = (ElfW(Addr))sym.addr + addend;

          LOGD("%s relocation at %p in %s: symbol '%s' resolved to %p", r->type == R_GENERIC_GLOB_DAT ? "R_GENERIC_GLOB_DAT" : "R_GENERIC_JUMP_SLOT", target_addr, dep->img->elf, sym_name, (void *)*target_addr);

          break;
        }
        case R_GENERIC_ABSOLUTE: {
          ElfW(Addr) addend = is_rela ? r->r_addend : *(ElfW(Addr) *)target_addr;
          *target_addr = (ElfW(Addr))sym.addr + addend;

          LOGD("R_GENERIC_ABSOLUTE relocation at %p in %s: symbol '%s' resolved to %p", target_addr, dep->img->elf, sym_name, (void *)*target_addr);

          break;
        }
        #ifdef __x86_64__
        case R_X86_64_32: {
          *target_addr = (ElfW(Addr))sym.addr + r->r_addend;

          LOGD("R_X86_64_32 relocation at %p in %s: symbol '%s' resolved to %p", target_addr, dep->img->elf, sym_name, (void *)*target_addr);

          break;
        }
        case R_X86_64_PC32: {
          *target_addr = (ElfW(Addr))sym.addr + r->r_addend - (ElfW(Addr))target_addr;

          LOGD("R_X86_64_PC32 relocation at %p in %s: symbol '%s' resolved to %p", target_addr, dep->img->elf, sym_name, (void *)*target_addr);

          break;
        }
        #elif defined(__i386__)
        case R_386_PC32: {
          ElfW(Addr) addend = is_rela ? r->r_addend : *(ElfW(Addr) *)target_addr;
          *target_addr = (ElfW(Addr))sym.addr + addend - (ElfW(Addr))target_addr;

          LOGD("R_386_PC32 relocation at %p in %s: symbol '%s' resolved to %p", target_addr, dep->img->elf, sym_name, (void *)*target_addr);

          break;
        }
        #endif
      }
      break;
    }
    case R_GENERIC_TLS_DTPMOD: {
      struct csoloader_elf *tls_img = NULL;
      size_t module_id = 0;
      
      if (r->sym_idx == 0) {
        /* INFO: If not referenced, assume current module */
        tls_img = dep->img;
      } else {
        ElfW(Sym) *sym_ent = &dynsym[r->sym_idx];
        uint8_t bind = ELF_ST_BIND(sym_ent->st_info);
        
        if (bind == STB_LOCAL) {
          LOGE("Unexpected TLS reference to STB_LOCAL symbol in %s", dep->img->elf);

          return false;
        }
        
        const char *sym_name = dynstr + sym_ent->st_name;
        struct linker_symbol_info sym = _linker_find_symbol_in_linker_scope(linker, dep->img, sym_name);
        
        if (!sym.img && bind != STB_WEAK) {
          LOGE("TLS symbol '%s' not found in %s", sym_name, dep->img->elf);

          return false;
        }
        
        /* INFO: NULLs are allowed for unresolved WEAKs */
        tls_img = sym.img;
      }
      
      if (tls_img && tls_img->tls_segment) module_id = tls_img->tls_mod_id;
      *target_addr = module_id;

      LOGD("TLS: R_GENERIC_TLS_DTPMOD at %p in %s: module_id=%zu", target_addr, dep->img->elf, module_id);

      break;
    }
    case R_GENERIC_TLS_DTPREL: {
      ElfW(Sym) *sym_ent = &dynsym[r->sym_idx];
      ElfW(Addr) offset = sym_ent->st_value + r->r_addend;
      *target_addr = offset;

      LOGD("TLS: R_GENERIC_TLS_DTPREL at %p in %s: offset=%zu", target_addr, dep->img->elf, (size_t)offset);

      break;
    }
    case R_GENERIC_TLSDESC: {
      struct csoloader_elf *tls_img = NULL;
      struct tls_indices_data *target_tls_indices = NULL;
      ElfW(Addr) *desc = target_addr;
      
      if (r->sym_idx == 0) {
        /* INFO: If not referenced, assume current module */
        tls_img = dep->img;
        target_tls_indices = &dep->tls_indices;
      } else {
        ElfW(Sym) *sym_ent = &dynsym[r->sym_idx];
        uint8_t bind = ELF_ST_BIND(sym_ent->st_info);
        
        if (bind == STB_LOCAL) {
          LOGE("Unexpected TLS reference to STB_LOCAL symbol in %s", dep->img->elf);

          return false;
        }
        
        const char *sym_name = dynstr + sym_ent->st_name;
        struct linker_symbol_info sym = _linker_find_symbol_in_linker_scope(linker, dep->img, sym_name);
        if (!sym.img) {
          if (bind != STB_WEAK)  {
            LOGE("TLS symbol '%s' not found for TLSDESC in %s", sym_name, dep->img->elf);

            return false;
          }

          /* INFO: Unresolved weak. Setup resolver that returns -tpidr + addend
                      so result is NULL + addend */
          desc[0] = (ElfW(Addr))&tlsdesc_resolver_unresolved_weak;
          desc[1] = r->r_addend;

          LOGD("TLS: R_GENERIC_TLSDESC at %p in %s: unresolved weak, addend=%zu", target_addr, dep->img->elf, (size_t)r->r_addend);

          break;
        }

        tls_img = sym.img;
        target_tls_indices = sym.tls_indices;
      }
      
      if (!tls_img || !tls_img->tls_segment) {
        LOGE("TLSDESC refers to module with no TLS segment in %s", dep->img->elf);

        return false;
      }

      struct tls_index *ti = allocate_tls_index_for_symbol(tls_img, target_tls_indices, dynsym, r->sym_idx, r->r_addend);
      if (!ti) {
        LOGE("Failed to allocate tls_index for TLSDESC in %s", dep->img->elf);

        return false;
      }

      desc[0] = (ElfW(Addr))&dynamic_tls_resolver;
      desc[1] = (ElfW(Addr))ti;

      LOGD("TLS: R_GENERIC_TLSDESC at %p in %s: resolver=%p, ti={mod=%zu,off=%zu}", target_addr, dep->img->elf, (void *)desc[0], (size_t)ti->module, (size_t)ti->offset);

      break;
    }
    case R_GENERIC_TLS_TPREL: {
      /* AOSP INFO: TLS symbol in dlopened library referenced using IE access model.
         
         INFO: Since CSOLoader only handles dlopen'd libraries, we cannot support
                 true static TLS. However, we can emulate by computing offset from tpidr. */
      struct csoloader_elf *tls_img = NULL;
      ElfW(Addr) tpoff = 0;
      
      if (r->sym_idx == 0) {
        /* INFO: If not referenced, assume current module */
        tls_img = dep->img;
      } else {
        ElfW(Sym) *sym_ent = &dynsym[r->sym_idx];
        uint8_t bind = ELF_ST_BIND(sym_ent->st_info);        
        if (bind == STB_LOCAL) {
          LOGE("Unexpected TLS reference to STB_LOCAL symbol in %s", dep->img->elf);

          return false;
        }
        
        const char *sym_name = dynstr + sym_ent->st_name;
        struct linker_symbol_info sym = _linker_find_symbol_in_linker_scope(linker, dep->img, sym_name);
        if (!sym.img) {
          if (bind != STB_WEAK) {
            LOGE("TLS symbol '%s' not found for TPREL in %s", sym_name, dep->img->elf);

            return false;
          }
            
          /* INFO: Unresolved weak. tpoff=0 so &symbol resolves to tpidr (thread pointer) */
          *target_addr = 0;

          LOGD("TLS: R_GENERIC_TLS_TPREL at %p in %s: unresolved weak, tpoff=0", target_addr, dep->img->elf);

          break;
        }

        tls_img = sym.img;
      }
      
      if (!tls_img || !tls_img->tls_segment) {
        LOGE("TLS_TPREL refers to module with no TLS segment in %s", dep->img->elf);

        return false;
      }

      ElfW(Sym) *sym_ent = &dynsym[r->sym_idx];
      struct tls_index ti = {
        .module = tls_img->tls_mod_id,
        .offset = sym_ent->st_value + r->r_addend
      };

      void *var_addr = __tls_get_addr(&ti);
      if (!var_addr) {
        LOGE("TLS: Failed to get TLS address for TPREL in %s", dep->img->elf);

        return false;
      }
      
      /* INFO: Store offset from tpidr so that tpidr + offset = var_addr */
      ElfW(Addr) tpidr = _linker_get_tpidr();
      tpoff = (ElfW(Addr))var_addr - tpidr;
      *target_addr = tpoff;

      LOGD("TLS: R_GENERIC_TLS_TPREL at %p in %s: tpoff=0x%lx (addr=%p, tpidr=0x%lx)", target_addr, dep->img->elf, (unsigned long)tpoff, var_addr, (unsigned long)tpidr);

      break;
    }
    default: {
      LOGF("Unsupported relocation type: %d in %s.\n - Symbol index: %d\n - Symbol name: %s\n - Offset: %p\n - Addend: %p",
           r->type, dep->img->elf, r->sym_idx, dynstr + dynsym[r->sym_idx].st_name,
           target_addr, (void *)r->r_addend);
    }
  }

  return true;
}

static bool _linker_process_relocations(struct linker *linker, struct loaded_dep *dep) {
  ElfW(Phdr) *phdr = (ElfW(Phdr) *)((uintptr_t)dep->img->header + dep->img->header->e_phoff);
  ElfW(Dyn) *dyn = NULL;
  for (int i = 0; i < dep->img->header->e_phnum; i++) {
    if (phdr[i].p_type != PT_DYNAMIC) continue;

    dyn = (ElfW(Dyn) *)((uintptr_t)dep->img->base + phdr[i].p_vaddr - dep->img->bias);

    break;
  }

  if (!dyn) {
    LOGD("No DYNAMIC section found in %s", dep->img->elf);

    return true;
  }

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
  ElfW(Addr) load_bias = (ElfW(Addr))dep->img->base - dep->img->bias;

  for (ElfW(Dyn) *d = dyn; d->d_tag != DT_NULL; ++d) {
    uintptr_t ptr_val = (uintptr_t)dep->img->base + d->d_un.d_ptr - dep->img->bias;

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
        case DT_ANDROID_RELR:   relr = (ElfW(Addr) *)ptr_val; break;
        case DT_ANDROID_RELRSZ: relr_sz = d->d_un.d_val; break;
        case DT_ANDROID_RELRENT: {
          if (d->d_un.d_val != sizeof(ElfW(Addr))) {
            LOGF("Unsupported DT_ANDROID_RELRENT size %zu in %s", (size_t)d->d_un.d_val, dep->img->elf);

            return false;
          }

          break;
        }
      #endif
    }
  }

  if (!dynsym || !dynstr) {
    LOGE("Could not find DT_SYMTAB or DT_STRTAB in %s", dep->img->elf);

    return false;
  }

  if (relr) {
    LOGD("Processing RELR relocations for %s", dep->img->elf);

    const size_t bits_per_entry = sizeof(ElfW(Addr)) * 8;
    ElfW(Addr) *relr_entries = relr;
    size_t relr_count = relr_sz / sizeof(ElfW(Addr));
    ElfW(Addr) load_bias = (ElfW(Addr))dep->img->base - dep->img->bias;
    ElfW(Addr) base_offset = 0;

    for (size_t i = 0; i < relr_count; i++) {
      ElfW(Addr) entry = relr_entries[i];

      if ((entry & 1) == 0) {
        /* INFO: Even entries encode an explicit address */
        ElfW(Addr) reloc_offset = entry;
        ElfW(Addr) *target_addr = (ElfW(Addr) *)(load_bias + reloc_offset);
        *target_addr += load_bias;

        base_offset = reloc_offset + sizeof(ElfW(Addr));

        LOGD("RELR direct relocation at offset 0x%llx", (unsigned long long)reloc_offset);

        continue;
      }

      /* INFO: Odd entries encode a bitmap of up to (bits_per_entry - 1) following words */
      ElfW(Addr) bitmap = entry >> 1;

      for (size_t bit = 0; bitmap != 0 && bit < bits_per_entry - 1; bit++, bitmap >>= 1) {
        if ((bitmap & 1) == 0) continue;

        ElfW(Addr) *target_addr = (ElfW(Addr) *)(load_bias + base_offset + (bit * sizeof(ElfW(Addr))));
        *target_addr += load_bias;

        LOGD("RELR bitmap relocation at offset 0x%llx", (unsigned long long)(base_offset + bit * sizeof(ElfW(Addr))));
      }

      base_offset += sizeof(ElfW(Addr)) * (bits_per_entry - 1);
    }
  }

  if (rela) {
    LOGD("Processing RELA relocations for %s", dep->img->elf);

    if (rela_ent == 0) rela_ent = sizeof(ElfW(Rela));

    for (size_t i = 0; i < rela_sz / rela_ent; ++i) {
      ElfW(Rela) *r = &rela[i];

      struct _linker_unified_r unified_r = {
        .sym_idx = ELF_R_SYM(r->r_info),
        .type = ELF_R_TYPE(r->r_info),
        .r_offset = r->r_offset,
        .r_addend = r->r_addend
      };

      if (!_linker_process_unified_relocation(linker, dep, &unified_r, load_bias, dynsym, dynstr, true)) return false;
    }
  }

  if (rel) {
    LOGD("Processing REL relocations for %s", dep->img->elf);

    if (rel_ent == 0) rel_ent = sizeof(ElfW(Rel));

    for (size_t i = 0; i < rel_sz / rel_ent; ++i) {
      ElfW(Rel) *r = &rel[i];

      struct _linker_unified_r unified_r = {
        .sym_idx = ELF_R_SYM(r->r_info),
        .type = ELF_R_TYPE(r->r_info),
        .r_offset = r->r_offset,
        .r_addend = 0
      };

      if (!_linker_process_unified_relocation(linker, dep, &unified_r, load_bias, dynsym, dynstr, false)) return false;
    }
  }

  #ifdef __ANDROID__
    if (android_reloc) {
      LOGD("Processing Android %s relocations for %s", is_rela ? "RELA" : "REL", dep->img->elf);

      if (memcmp(android_reloc, "APS2", 4) != 0) {
        LOGE("Invalid Android %s magic in %s", is_rela ? "RELA" : "REL", dep->img->elf);

        return false;
      }

      const uint8_t *packed_data = (const uint8_t *)android_reloc + 4;
      size_t packed_size = android_reloc_sz - 4;

      sleb128_decoder decoder;
      sleb128_decoder_init(&decoder, packed_data, packed_size);

      uint64_t num_relocs = sleb128_decode(&decoder);

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

        for (size_t j = 0; j < group_size; ++j) {
          if (group_flags & RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG) {
            unified_r.r_offset += group_r_offset_delta;
          } else {
            unified_r.r_offset += sleb128_decode(&decoder);
          }
          if ((group_flags & RELOCATION_GROUPED_BY_INFO_FLAG) == 0) {
            ElfW(Addr) r_info = sleb128_decode(&decoder);
            unified_r.sym_idx = ELF_R_SYM(r_info);
            unified_r.type = ELF_R_TYPE(r_info);

            LOGD("Group %llu: r_info: %llu, sym_idx: %u, type: %u", (unsigned long long)j, (unsigned long long)r_info, unified_r.sym_idx, unified_r.type);
          }

          if (is_rela && group_flags_reloc == RELOCATION_GROUP_HAS_ADDEND_FLAG)
            unified_r.r_addend += sleb128_decode(&decoder);

          if (!_linker_process_unified_relocation(linker, dep, &unified_r, load_bias, dynsym, dynstr, is_rela)) return false;
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
    LOGD("Processing %s PLT relocations for %s", pltrel_type == DT_RELA ? "RELA" : "REL", dep->img->elf);

    if (pltrel_type == DT_RELA) {
      for (ElfW(Rela) *r = jmprel; (void *)r < (void *)jmprel + jmprel_sz; r++) {
        LOGD("Processing PLT relocation of type %llu for %s", (unsigned long long)ELF_R_TYPE(r->r_info), dep->img->elf);

        struct _linker_unified_r unified_r = {
          .sym_idx = ELF_R_SYM(r->r_info),
          .type = ELF_R_TYPE(r->r_info),
          .r_offset = r->r_offset,
          .r_addend = pltrel_type == DT_RELA ? r->r_addend : 0
        };

        if (!_linker_process_unified_relocation(linker, dep, &unified_r, load_bias, dynsym, dynstr, true)) return false;
      }
    } else {
      for (ElfW(Rel) *r = jmprel; (void *)r < (void *)jmprel + jmprel_sz; r++) {
        LOGD("Processing PLT relocation of type %llu for %s", (unsigned long long)ELF_R_TYPE(r->r_info), dep->img->elf);

        struct _linker_unified_r unified_r = {
          .sym_idx = ELF_R_SYM(r->r_info),
          .type = ELF_R_TYPE(r->r_info),
          .r_offset = r->r_offset,
          .r_addend = 0
        };

        if (!_linker_process_unified_relocation(linker, dep, &unified_r, load_bias, dynsym, dynstr, false)) return false;
      }
    }
  }

  return true;
}

static bool _linker_is_library_loaded(struct linker *linker, const char *lib_name) {
  if (strstr(linker->img->elf, lib_name)) return true;

  for (int i = 0; i < linker->dep_count; i++) {
    if (strstr(linker->dependencies[i].img->elf, lib_name)) return true;
  }

  return false;
}

static void _linker_restore_protections(struct csoloader_elf *image) {
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

    if (final_prot != 0 && mprotect((void *)current_page, system_page_size, final_prot) != 0) {
      LOGW("mprotect failed to restore prot %d for page %p in %s: %s", final_prot, (void *)current_page, image->elf, strerror(errno));
    } else if ((final_prot & PROT_EXEC) && (final_prot & PROT_READ)) {
      __builtin___clear_cache((char *)current_page, (char *)current_page + system_page_size);
    }
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
      if (phdr[i].p_type != PT_DYNAMIC) continue;

      dyn = (ElfW(Dyn) *)((uintptr_t)linker->img->base + phdr[i].p_vaddr - linker->img->bias);
      
      break;
    }

    if (dyn) for (ElfW(Dyn) *d = dyn; d->d_tag != DT_NULL; ++d) {
      if (d->d_tag != DT_NEEDED) continue;

      const char *dep_name = (const char *)linker->img->strtab_start + d->d_un.d_val;
      if (strcmp(dep_name, "ld-android.so") == 0) {
        LOGD("Skipping internal linker dependency: %s", dep_name);

        continue;
      }

      LOGD("Found needed dependency in main image: %s", dep_name);

      if (!carray_add(loaded_libs, dep_name)) {
        LOGE("Failed to add dependency to loaded libraries array");

        carray_destroy(loaded_libs);

        return false;
      }
    }
  }

  for (size_t i = 0; i < carray_length(loaded_libs); i++) {
    char *lib_name = carray_get(loaded_libs, i);
    if (!lib_name) {
      LOGE("Loaded library name is NULL");

      carray_destroy(loaded_libs);

      return false;
    }

    char lib_full_path[PATH_MAX];
    if (!_linker_find_library_path(lib_name, lib_full_path, sizeof(lib_full_path))) {
      LOGW("Could not find required library: %s", lib_name);

      /* INFO: Rather than failing, just skip missing libraries.
                 This allows loading libraries with optional dependencies. */
      carray_remove(loaded_libs, lib_name);
      i--;

      continue;
    }

    if (_linker_is_library_loaded(linker, lib_full_path)) {
      LOGD("Library already loaded: %s", lib_full_path);

      continue;
    }

    if (linker->dep_count >= MAX_DEPS) {
      LOGE("Maximum dependency count (%d) exceeded while loading: %s", MAX_DEPS, lib_full_path);

      carray_destroy(loaded_libs);

      return false;
    }

    struct loaded_dep *current_dep = &linker->dependencies[linker->dep_count];

    struct csoloader_elf *check_img = csoloader_elf_create(lib_name, NULL);
    if (check_img && check_img->base) {
      current_dep->img = check_img;
      current_dep->is_manual_load = false;
    } else {
      void *base_addr = linker_load_library_manually(lib_full_path, current_dep);
      if (!base_addr) {
        LOGE("Failed to manually load library: %s", lib_full_path);

        if (check_img) csoloader_elf_destroy(check_img);
        carray_destroy(loaded_libs);

        return false;
      }

      current_dep->img = csoloader_elf_create(lib_full_path, base_addr);
      if (!current_dep->img) {
        LOGE("Failed to create ELF image for manually loaded library: %s", lib_full_path);

        if (check_img) csoloader_elf_destroy(check_img);
        carray_destroy(loaded_libs);

        return false;
      }

      current_dep->is_manual_load = true;

      csoloader_elf_destroy(check_img);
    }

    if (!current_dep->img) {
      LOGE("Failed to create ELF image for: %s", lib_full_path);

      carray_destroy(loaded_libs);

      return false;
    }

    linker->dep_count++;

    if (current_dep->is_manual_load && current_dep->img->header->e_phoff > 0 && current_dep->img->header->e_phnum > 0) {
      ElfW(Phdr) *dep_phdr = (ElfW(Phdr) *)((uintptr_t)current_dep->img->header + current_dep->img->header->e_phoff);
      ElfW(Dyn) *dep_dyn = NULL;

      for (int i = 0; i < current_dep->img->header->e_phnum; i++) {
        if (dep_phdr[i].p_type != PT_DYNAMIC) continue;

        dep_dyn = (ElfW(Dyn) *)((uintptr_t)current_dep->img->base + dep_phdr[i].p_vaddr - current_dep->img->bias);
        
        break;
      }

      if (dep_dyn) for (ElfW(Dyn) *d = dep_dyn; d->d_tag != DT_NULL; ++d) {
        if (d->d_tag != DT_NEEDED) continue;

        const char *dep_name = (const char *)current_dep->img->strtab_start + d->d_un.d_val;
        if (strcmp(dep_name, "ld-android.so") == 0) {
          LOGD("Skipping internal linker dependency in %s: %s", current_dep->img->elf, dep_name);

          continue;
        }

        if (carray_exists(loaded_libs, dep_name)) {
          LOGD("Dependency already loaded: %s", dep_name);

          continue;
        }

        LOGD("Found needed dependency in %s: %s", current_dep->img->elf, dep_name);

        if (!carray_add(loaded_libs, dep_name)) {
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
    if (!dep->is_manual_load) continue;

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
    size_t page_len = _page_end(main_phdr[j].p_vaddr + main_phdr[j].p_memsz) - _page_start(main_phdr[j].p_vaddr);

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
      size_t page_len = _page_end(dep_phdr[j].p_vaddr + dep_phdr[j].p_memsz) - _page_start(dep_phdr[j].p_vaddr);

      if (mprotect(page_start, page_len, PROT_READ | PROT_WRITE | (dep_phdr[j].p_flags & PF_X ? PROT_EXEC : 0)) != 0)
        LOGW("mprotect failed for make segment %d in %s writable: %s", j, dep->img->elf, strerror(errno));
    }
  }

  LOGD("Processing relocations for main library and dependencies.");
  if (!_linker_process_relocations(linker, (struct loaded_dep *)linker)) {
    LOGE("Failed processing relocations for main library: %s", linker->img->elf);

    return false;
  }

  for (int i = 0; i < linker->dep_count; i++) {
    if (!linker->dependencies[i].is_manual_load) continue;

    if (!_linker_process_relocations(linker, &linker->dependencies[i])) {
      LOGE("Failed processing relocations for dependency: %s", linker->dependencies[i].img->elf);

      return false;
    }
  }

  LOGD("Restoring memory protections after relocations");
  _linker_restore_protections(linker->img);

  for (int i = 0; i < linker->dep_count; i++) {
    struct loaded_dep *dep = &linker->dependencies[i];
    if (!dep->is_manual_load) continue;

    _linker_restore_protections(dep->img);
  }

  LOGD("Applying GNU RELRO protection for main library and dependencies.");
  if (_linker_protect_gnu_relro(linker->img) != 0) {
    LOGW("Failed to apply GNU RELRO protection to main library");
  }

  for (int i = 0; i < linker->dep_count; i++) {
    if (!linker->dependencies[i].is_manual_load) continue;

    if (_linker_protect_gnu_relro(linker->dependencies[i].img) != 0) {
      LOGW("Failed to apply GNU RELRO protection to %s", linker->dependencies[i].img->elf);
    }
  }

  if (!register_custom_library_for_backtrace(linker->img))
    LOGW("Failed to register main library for backtrace support");

  register_eh_frame_for_library(linker->img);

  for (int i = 0; i < linker->dep_count; i++) {
    struct loaded_dep *dep = &linker->dependencies[i];
    if (!dep->is_manual_load) continue;

    if (!register_custom_library_for_backtrace(dep->img)) {
      LOGW("Failed to register dependency %s for backtrace support", dep->img->elf);
    }

    register_eh_frame_for_library(dep->img);
  }

  /* INFO: preinit only is for the main EXECUTABLE. We don't deal with those, not for now, as
             we are not a system linker that needs to start off everything. */
  // _linker_call_preinit_constructors(linker->img);

  /* TODO: Simplify this (constructors calling).. it's a mess, but it works great */
  /* INFO: Dependencies have their constructors called before the main elf.
             A manual dependency runs only after its manual DT_NEEDED deps. */
  unsigned char constructor_state[MAX_DEPS] = { 0 };
  for (int i = 0; i < linker->dep_count; i++) {
    if (!linker->dependencies[i].is_manual_load) continue;

    _linker_call_manual_constructors(linker, i, constructor_state);
  }

  for (int i = 0; i < linker->dep_count; i++) {
    struct loaded_dep *dep = &linker->dependencies[i];
    if (!dep->is_manual_load || constructor_state[i] == 2) continue;

    _linker_call_constructors(dep->img);
    constructor_state[i] = 2;
  }

  _linker_call_constructors(linker->img);

  linker->is_linked = true;

  return true;
}

void linker_deinit(void) {
  struct thread_tls *ttls = (struct thread_tls *)pthread_getspecific(g_tls_key);
  if (ttls) _linker_destroy_thread_tls(ttls);
  pthread_setspecific(g_tls_key, NULL);

  pthread_key_delete(g_tls_key);
  g_tls_key_initialized = false;
  g_tls_key_once = PTHREAD_ONCE_INIT;

  g_tls_generation = 0;
  memset(&g_tls_modules, 0, sizeof(g_tls_modules));

  pthread_mutex_destroy(&g_tls_mutex);
  g_tls_mutex = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
}