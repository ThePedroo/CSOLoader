/* Copyright (c) 2025 ThePedroo. All rights reserved.
 *
 * This source code is licensed under the GNU AGPLv3 License found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <link.h>
#include <dlfcn.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdint.h>
#include <unwind.h>

#include "elf_util.h"
#include "linker.h"
#include "logging.h"

/* INFO: System libunwind functions */
void __register_frame(void *eh_frame) __attribute__((weak));
void __deregister_frame(void *eh_frame) __attribute__((weak));

#define MAX_CUSTOM_LIBS 64

struct custom_lib_info {
  struct csoloader_elf *img;
  struct dl_phdr_info phdr_info;
  bool in_use;
  void *eh_frame_registered;
};

/* TODO: Transform into a dynamic structure to remove limitations */
static struct custom_lib_info g_custom_libs[MAX_CUSTOM_LIBS];
static pthread_mutex_t g_custom_libs_mutex = PTHREAD_MUTEX_INITIALIZER;

/* INFO: Minimal readers for decoding .eh_frame_hdr when section headers are absent */
static uint64_t read_uleb128(const uint8_t **p, const uint8_t *end) {
  const uint8_t *s = *p;
  uint64_t r = 0;
  unsigned shift = 0;

  while (s < end) {
    uint8_t b = *s++;
    r |= ((uint64_t)(b & 0x7f)) << shift;
  
    if ((b & 0x80) == 0) break;
  
    shift += 7;
  
    if (shift >= 64) break;
  }

  *p = s;

  return r;
}

/* DW_EH_PE encodings used in .eh_frame_hdr */
#define DW_EH_PE_omit     0xff
#define DW_EH_PE_ptr      0x00
#define DW_EH_PE_uleb128  0x01
#define DW_EH_PE_udata2   0x02
#define DW_EH_PE_udata4   0x03
#define DW_EH_PE_udata8   0x04
#define DW_EH_PE_sdata2   0x0a
#define DW_EH_PE_sdata4   0x0b
#define DW_EH_PE_sdata8   0x0c

#define DW_EH_PE_absptr   0x00
#define DW_EH_PE_pcrel    0x10
#define DW_EH_PE_datarel  0x30
#define DW_EH_PE_indirect 0x80

static uintptr_t decode_eh_value(uint8_t enc, const uint8_t **p, uintptr_t base, uintptr_t data_base, const uint8_t *end) {
  if (enc == DW_EH_PE_omit) return 0;

  uint8_t fmt = enc & 0x0f;
  uint8_t app = enc & 0x70;
  int indir = (enc & DW_EH_PE_indirect) != 0;

  uintptr_t value = 0;
  #define READ_VALUE(type, cast_type) do {          \
    type raw = 0;                                   \
    if ((size_t)(end - *p) < sizeof(raw)) return 0; \
                                                    \
    memcpy(&raw, *p, sizeof(raw));                  \
    *p += sizeof(raw);                              \
    value = (uintptr_t)(cast_type)raw;              \
  } while (0)

  switch (fmt) {
    case DW_EH_PE_ptr: {
      #ifdef __LP64__
        READ_VALUE(uint64_t, uint64_t);
      #else
        READ_VALUE(uint32_t, uint32_t);
      #endif

      break;
    }
    case DW_EH_PE_uleb128: {
      value = (uintptr_t)read_uleb128(p, end);

      break;
    }
    case DW_EH_PE_udata2: {
      READ_VALUE(uint16_t, uint16_t);

      break;
    }
    case DW_EH_PE_udata4: {
      READ_VALUE(uint32_t, uint32_t);

      break;
    }
    case DW_EH_PE_udata8: {
      READ_VALUE(uint64_t, uint64_t);

      break;
    }
    case DW_EH_PE_sdata2: {
      READ_VALUE(uint16_t, int16_t);

      break;
    }
    case DW_EH_PE_sdata4: {
      READ_VALUE(uint32_t, int32_t);

      break;
    }
    case DW_EH_PE_sdata8: {
      READ_VALUE(uint64_t, int64_t);

      break;
    }
    default: return 0;
  }

  switch (app) {
    case DW_EH_PE_absptr: break;
    case DW_EH_PE_pcrel: value += base; break;
    case DW_EH_PE_datarel: value += data_base; break;
    default: break;
  }

  if (indir) {
    if (!value) {
      LOGE("Failed to decode indirect .eh_frame_hdr value: pointer is NULL");

      return 0;
    }

    value = *(const uintptr_t *)(const void *)value;
  }

  return value;

  #undef READ_VALUE
}

static int locate_eh_frame_ptr(struct csoloader_elf *img, void **out_ptr, size_t *out_size) {
  *out_ptr = NULL;
  if (out_size) *out_size = 0;

  if (img->eh_frame) {
    *out_ptr = (void *)img->eh_frame;
    if (out_size) *out_size = img->eh_frame_size;

    return 0;
  }

  /* INFO: Try to find .eh_frame (direct) first */
  if (img->section_header && img->header->e_shstrndx != SHN_UNDEF && img->header->e_shstrndx < img->header->e_shnum) {
    ElfW(Shdr) *shstr = img->section_header + img->header->e_shstrndx;
    char *names = (char *)((uintptr_t)img->header + shstr->sh_offset);
    if (names) {
      for (int i = 0; i < img->header->e_shnum; i++) {
        ElfW(Shdr) *sh = img->section_header + i;
        const char *sname = names + sh->sh_name;
        if (!sname || strcmp(sname, ".eh_frame") != 0) continue;

        *out_ptr = (void *)((uintptr_t)img->base + sh->sh_addr - img->bias);
        if (out_size) *out_size = sh->sh_size;
  
        return 0;
      }
    }
  }

  /* INFO: Fallback to PT_GNU_EH_FRAME, then decode hdr to get eh_frame_ptr */
  if (img->header->e_phoff > 0 && img->header->e_phnum > 0) {
    ElfW(Phdr) *phdr = (ElfW(Phdr) *)((uintptr_t)img->header + img->header->e_phoff);
    for (int i = 0; i < img->header->e_phnum; i++) {
      if (phdr[i].p_type != PT_GNU_EH_FRAME) continue;

      const uint8_t *hdr = (const uint8_t *)((uintptr_t)img->base + phdr[i].p_vaddr - img->bias);
      size_t hdr_sz = phdr[i].p_memsz;

      if (!hdr || hdr_sz < 4) {
        LOGW("PT_GNU_EH_FRAME too small for %s", img->elf);

        continue;
      }

      const uint8_t *p = hdr;
      const uint8_t *end = hdr + hdr_sz;

      uint8_t version = *p++;
      uint8_t eh_frame_ptr_enc = *p++;
      uint8_t fde_count_enc = *p++;
      uint8_t table_enc = *p++;

      (void)table_enc;
      (void)fde_count_enc;

      if (version != 1) {
        LOGW(".eh_frame_hdr version %u not supported (image %s)", version, img->elf);

        continue;
      }

      /* INFO: eh_frame_ptr follows next. For pcrel, base is address of the encoded field */
      uintptr_t eh_frame_ptr = decode_eh_value(eh_frame_ptr_enc, &p, (uintptr_t)p, (uintptr_t)hdr, end);
      if (!eh_frame_ptr) {
        LOGW("Failed to decode eh_frame_ptr in %s", img->elf);

        continue;
      }

      *out_ptr = (void *)eh_frame_ptr;
      if (out_size) *out_size = 0;

      LOGD("Located .eh_frame via PT_GNU_EH_FRAME in %s at %p", img->elf, *out_ptr);

      return 0;
    }
  }

  LOGW("Failed to locate .eh_frame for %s", img->elf);

  return -1;
}

/* TODO: Implement dl_iterate_eaidx */
int custom_dl_iterate_phdr(int (*callback)(struct dl_phdr_info *, size_t, void *), void *data) {
  /* INFO: Must be resolved via dl_iterate_phdr to ensure we don't enter 
             a loop, see our "hook" for dladdr in the code below. */
  static int (*original_dl_iterate_phdr)(int (*callback)(struct dl_phdr_info *, size_t, void *), void *);
  if (!original_dl_iterate_phdr) {
    struct csoloader_elf *libdl_elf = csoloader_elf_create("libdl.so", NULL);
    if (!libdl_elf) {
      LOGE("Failed to open libdl.so via csoloader_elf");

      return 0;
    }

    original_dl_iterate_phdr = (int (*)(int (*)(struct dl_phdr_info *, size_t, void *), void *))csoloader_elf_symb_address(libdl_elf, "dl_iterate_phdr");
    csoloader_elf_destroy(libdl_elf);
    if (!original_dl_iterate_phdr) {
      LOGE("Failed to locate original dl_iterate_phdr in libdl.so");

      return 0;
    }
  }

  int result = original_dl_iterate_phdr(callback, data);
  if (result != 0) return result;

  pthread_mutex_lock(&g_custom_libs_mutex);
  for (int i = 0; i < MAX_CUSTOM_LIBS; i++) {
    if (!g_custom_libs[i].in_use) continue;

    result = callback(&g_custom_libs[i].phdr_info, sizeof(struct dl_phdr_info), data);
    if (result != 0) break;
  }
  pthread_mutex_unlock(&g_custom_libs_mutex);

  return result;
}

/* INFO: libc functions such as backtrace rely on the below functions. Since we
           "cannot" tamper the PLT of libc to redirect for our functions, we must
           declare them here, so that the system linker understands where we want
           it to call. */
/* INFO: Disable it, as it will cause infinite recursion. If one day we use it as
           main linker, it won't even need to search in the system linker anyway. */
// int dl_iterate_phdr(int (*callback)(struct dl_phdr_info *, size_t, void *), void *data) {
//   return custom_dl_iterate_phdr(callback, data);
// }

int custom_dladdr(const void *addr, Dl_info *info) {
  /* INFO: Must be resolved via dladdr to ensure we don't enter a loop, see our
             "hook" for dladdr in the code below. */
  static int (*original_dladdr)(const void *, Dl_info *);
  if (!original_dladdr) {
    struct csoloader_elf *libdl_elf = csoloader_elf_create("libdl.so", NULL);
    if (!libdl_elf) {
      LOGE("Failed to open libdl.so via csoloader_elf");

      return 0;
    }

    original_dladdr = (int (*)(const void *, Dl_info *))csoloader_elf_symb_address(libdl_elf, "dladdr");
    csoloader_elf_destroy(libdl_elf);
    if (!original_dladdr) {
      LOGE("Failed to locate original dladdr in libdl.so");

      return 0;
    }
  }

  if (original_dladdr(addr, info))
    return 1;

  pthread_mutex_lock(&g_custom_libs_mutex);
  for (int i = 0; i < MAX_CUSTOM_LIBS; i++) {
    if (!g_custom_libs[i].in_use) continue;

    bool in_range = false;

    if (g_custom_libs[i].phdr_info.dlpi_phdr && g_custom_libs[i].phdr_info.dlpi_phnum > 0) {
      for (size_t ph = 0; ph < g_custom_libs[i].phdr_info.dlpi_phnum; ph++) {
        ElfW(Phdr) *phdr = (ElfW(Phdr) *)&g_custom_libs[i].phdr_info.dlpi_phdr[ph];
        if (phdr->p_type != PT_LOAD) continue;

        uintptr_t seg_start = (uintptr_t)g_custom_libs[i].phdr_info.dlpi_addr + phdr->p_vaddr;
        uintptr_t seg_end = seg_start + phdr->p_memsz;

        if ((uintptr_t)addr >= seg_start && (uintptr_t)addr < seg_end) in_range = true;
      }
    }

    if (!in_range) continue;

    info->dli_fname = g_custom_libs[i].phdr_info.dlpi_name;
    info->dli_fbase = (void *)g_custom_libs[i].phdr_info.dlpi_addr;

    struct sym_info sym = csoloader_elf_get_symbol(g_custom_libs[i].img, (uintptr_t)addr);
    if (sym.name) {
      info->dli_sname = sym.name;
      info->dli_saddr = (void *)sym.address;
    } else {
      info->dli_sname = NULL;
      info->dli_saddr = NULL;
    }

    pthread_mutex_unlock(&g_custom_libs_mutex);

    return 1;
  }
  pthread_mutex_unlock(&g_custom_libs_mutex);

  return 0;
}

/* INFO: libc functions such as backtrace rely on the below functions. Since we
           "cannot" tamper the PLT of libc to redirect for our functions, we must
           declare them here, so that the system linker understands where we want
           it to call. */
/* INFO: Disable it, as it will cause infinite recursion. If one day we use it as
           main linker, it won't even need to search in the system linker anyway. */
// int dladdr(const void *addr, Dl_info *info) {
//   return custom_dladdr(addr, info);
// }

bool register_custom_library_for_backtrace(struct csoloader_elf *img) {
  pthread_mutex_lock(&g_custom_libs_mutex);

  struct custom_lib_info *lib_info = NULL;
  for (int i = 0; i < MAX_CUSTOM_LIBS; i++) {
    if (g_custom_libs[i].in_use) continue;
    
    lib_info = &g_custom_libs[i];

    break;
  }

  if (!lib_info) {
    pthread_mutex_unlock(&g_custom_libs_mutex);

    LOGE("No available slots for custom library registration");

    return false;
  }

  lib_info->phdr_info.dlpi_addr = (ElfW(Addr))img->base - img->bias;
  lib_info->phdr_info.dlpi_name = img->elf;
  lib_info->phdr_info.dlpi_phdr = (ElfW(Phdr) *)((uintptr_t)img->base + img->header->e_phoff);
  lib_info->phdr_info.dlpi_phnum = img->header->e_phnum;
  lib_info->phdr_info.dlpi_adds = 1;
  lib_info->phdr_info.dlpi_subs = 0;
  lib_info->phdr_info.dlpi_tls_modid = img->tls_segment ? img->tls_mod_id : 0;
  lib_info->phdr_info.dlpi_tls_data = NULL;

  lib_info->img = img;
  lib_info->in_use = true;
  lib_info->eh_frame_registered = NULL;

  pthread_mutex_unlock(&g_custom_libs_mutex);

  return true;
}

bool unregister_custom_library_for_backtrace(struct csoloader_elf *img) {
  pthread_mutex_lock(&g_custom_libs_mutex);

  for (int i = 0; i < MAX_CUSTOM_LIBS; i++) {
    if (!g_custom_libs[i].in_use || g_custom_libs[i].img != img) continue;

    if (g_custom_libs[i].eh_frame_registered) {
      __deregister_frame(g_custom_libs[i].eh_frame_registered);

      LOGD("Deregistered .eh_frame for %s", img->elf);

      g_custom_libs[i].eh_frame_registered = NULL;
    }

    memset(&g_custom_libs[i], 0, sizeof(struct custom_lib_info));

    pthread_mutex_unlock(&g_custom_libs_mutex);

    LOGD("Unregistered custom library for backtrace support");

    return true;
  }

  pthread_mutex_unlock(&g_custom_libs_mutex);

  return false;
}

void register_eh_frame_for_library(struct csoloader_elf *img) {
  #ifdef __arm__
    (void)img; (void)locate_eh_frame_ptr;
  
    LOGD("Skipping .eh_frame registration on ARM32 (EHABI)");

    return;
  #else
    void *eh_frame_ptr = NULL;
    size_t eh_frame_size = 0;
    if (locate_eh_frame_ptr(img, &eh_frame_ptr, &eh_frame_size) != 0 || !eh_frame_ptr) {
      LOGW("No .eh_frame found for %s; exceptions may fail", img->elf);

      return;
    }

    LOGD("Registering .eh_frame at %p (size ~%zu) for %s", eh_frame_ptr, eh_frame_size, img->elf);

    if (__register_frame) {
      __register_frame(eh_frame_ptr);
      LOGD("Registered .eh_frame at %p (size ~%zu) for %s", eh_frame_ptr, eh_frame_size, img->elf);
    } else {
      LOGW("__register_frame not available; skipping .eh_frame registration for %s", img->elf);
      return;
    }

    /* INFO: Store for deregistration */
    pthread_mutex_lock(&g_custom_libs_mutex);
    for (int i = 0; i < MAX_CUSTOM_LIBS; i++) {
      if (!g_custom_libs[i].in_use || g_custom_libs[i].img != img) continue;

      g_custom_libs[i].eh_frame_registered = eh_frame_ptr;

      break;
    }

    pthread_mutex_unlock(&g_custom_libs_mutex);
  #endif
}

void unregister_eh_frame_for_library(struct csoloader_elf *img) {
  #ifdef __arm__
    (void)img;
  #else
    /* INFO: Deregister using stored pointer if available */
    pthread_mutex_lock(&g_custom_libs_mutex);

    for (int i = 0; i < MAX_CUSTOM_LIBS; i++) {
      if (!g_custom_libs[i].in_use || g_custom_libs[i].img != img || !g_custom_libs[i].eh_frame_registered) continue;

      __deregister_frame(g_custom_libs[i].eh_frame_registered);
      g_custom_libs[i].eh_frame_registered = NULL;

      LOGD("Deregistered .eh_frame for %s", img->elf);

      break;
    }

    pthread_mutex_unlock(&g_custom_libs_mutex);
  #endif
}
