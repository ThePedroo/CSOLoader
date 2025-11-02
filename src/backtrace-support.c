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

void __register_frame(void *eh_frame) __attribute__((weak));
void __deregister_frame(void *eh_frame) __attribute__((weak));

#define MAX_CUSTOM_LIBS 64

struct custom_lib_info {
  ElfImg *img;
  struct dl_phdr_info phdr_info;
  bool in_use;
  ElfW(Phdr) *phdr_copy;

  /* INFO: Broken! */
  void *eh_frame_registered;
  size_t eh_frame_size;
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

static size_t ptr_size(void) {
#ifdef __LP64__
  return 8;
#else
  return 4;
#endif
}

static int read_u16(const uint8_t **p, const uint8_t *end, uint16_t *out) {
  if ((size_t)(end - *p) < 2) return -1;
  uint16_t v;
  memcpy(&v, *p, 2);
  *p += 2;
  *out = v;
  return 0;
}

static int read_u32(const uint8_t **p, const uint8_t *end, uint32_t *out) {
  if ((size_t)(end - *p) < 4) return -1;
  uint32_t v;
  memcpy(&v, *p, 4);
  *p += 4;
  *out = v;
  return 0;
}

static int read_u64(const uint8_t **p, const uint8_t *end, uint64_t *out) {
  if ((size_t)(end - *p) < 8) return -1;
  uint64_t v;
  memcpy(&v, *p, 8);
  *p += 8;
  *out = v;
  return 0;
}

static uintptr_t decode_eh_value(uint8_t enc, const uint8_t **p, uintptr_t base, uintptr_t data_base, const uint8_t *end) {
  if (enc == DW_EH_PE_omit) return 0;

  uint8_t fmt = enc & 0x0f;
  uint8_t app = enc & 0x70;
  int indir = (enc & DW_EH_PE_indirect) != 0;

  uintptr_t value = 0;
  switch (fmt) {
    case DW_EH_PE_ptr: {
      #ifdef __LP64__
        if (read_u64(p, end, (uintptr_t *)&value) != 0) return 0;
      #else
        if (read_u32(p, end, (uintptr_t *)&value) != 0) return 0;
      #endif

      break;
    }
    case DW_EH_PE_uleb128: {
      value = (uintptr_t)read_uleb128(p, end);

      break;
    }
    case DW_EH_PE_udata2: {
      if (read_u16(p, end, (uint16_t *)&value) != 0) return 0;

      break;
    }
    case DW_EH_PE_udata4: {
      if (read_u32(p, end, (uint32_t *)&value) != 0) return 0;

      break;
    }
    case DW_EH_PE_udata8: {
      if (read_u64(p, end, (uint64_t *)&value) != 0) return 0;

      break;
    }
    case DW_EH_PE_sdata2: {
      if (read_u16(p, end, (uint16_t *)&value) != 0) return 0;

      break;
    }
    case DW_EH_PE_sdata4: {
      if (read_u32(p, end, (uint32_t *)&value) != 0) return 0;

      break;
    }
    case DW_EH_PE_sdata8: {
      if (read_u64(p, end, (uint64_t *)&value) != 0) return 0;

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

  if (indir) value = *(const uintptr_t *)(const void *)value;

  return value;
}

static int locate_eh_frame_ptr(ElfImg *img, void **out_ptr, size_t *out_size) {
  *out_ptr = NULL;
  if (out_size) *out_size = 0;

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

  LOGW("Could not locate .eh_frame for %s", img->elf);

  return -1;
}

int custom_dl_iterate_phdr(int (*callback)(struct dl_phdr_info *, size_t, void *), void *data) {
  /* INFO: Must be resolved via dl_iterate_phdr to ensure we don't enter 
             a loop, see our "hook" for dladdr in the code below. */
  int (*original_dl_iterate_phdr)(int (*callback)(struct dl_phdr_info *, size_t, void *), void *) = dlsym(RTLD_NEXT, "dl_iterate_phdr");

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
int dl_iterate_phdr(int (*callback)(struct dl_phdr_info *, size_t, void *), void *data) {
  return custom_dl_iterate_phdr(callback, data);
}

int custom_dladdr(const void *addr, Dl_info *info) {
  /* INFO: Must be resolved via dladdr to ensure we don't enter a loop, see our
             "hook" for dladdr in the code below. */
  int (*original_dladdr)(const void *, Dl_info *) = dlsym(RTLD_NEXT, "dladdr");

  if (original_dladdr(addr, info))
    return 1;

  pthread_mutex_lock(&g_custom_libs_mutex);
  for (int i = 0; i < MAX_CUSTOM_LIBS; i++) {
    if (!g_custom_libs[i].in_use) continue;

    bool in_range = false;

    uintptr_t seg_min = (uintptr_t)-1;
    uintptr_t seg_max = 0;
    bool have_segments = false;

    if (g_custom_libs[i].phdr_info.dlpi_phdr && g_custom_libs[i].phdr_info.dlpi_phnum > 0) {
      for (size_t ph = 0; ph < g_custom_libs[i].phdr_info.dlpi_phnum; ph++) {
        ElfW(Phdr) *phdr = (ElfW(Phdr) *)&g_custom_libs[i].phdr_info.dlpi_phdr[ph];
        if (phdr->p_type != PT_LOAD) continue;

        uintptr_t seg_start = (uintptr_t)g_custom_libs[i].phdr_info.dlpi_addr + phdr->p_vaddr;
        uintptr_t seg_end = seg_start + phdr->p_memsz;

        if (!have_segments || seg_start < seg_min) seg_min = seg_start;
        if (!have_segments || seg_end > seg_max) seg_max = seg_end;
        have_segments = true;

        if ((uintptr_t)addr >= seg_start && (uintptr_t)addr < seg_end) in_range = true;
      }
    }

    if (have_segments) {
      LOGD("custom_dladdr: custom lib %s segments cover %p - %p", g_custom_libs[i].phdr_info.dlpi_name, (void *)seg_min, (void *)seg_max);
      LOGD("custom_dladdr: checking if address %p falls in any segment", addr);
    } else {
      LOGD("custom_dladdr: custom lib %s has no loadable segments", g_custom_libs[i].phdr_info.dlpi_name);
    }

    if (!in_range) continue;

    info->dli_fname = g_custom_libs[i].phdr_info.dlpi_name;
    info->dli_fbase = (void *)g_custom_libs[i].phdr_info.dlpi_addr;

    struct sym_info sym = elf_get_symbol(g_custom_libs[i].img, (uintptr_t)addr);
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
int dladdr(const void *addr, Dl_info *info) {
  return custom_dladdr(addr, info);
}

static ElfW(Phdr) *copy_program_headers(ElfImg *img) {
  size_t phdr_size = img->header->e_phnum * sizeof(ElfW(Phdr));
  ElfW(Phdr) *phdr_copy = (ElfW(Phdr) *)malloc(phdr_size);
  if (!phdr_copy) {
    LOGE("Failed to allocate memory for program header copy");

    return NULL;
  }

  ElfW(Phdr) *original_phdr = (ElfW(Phdr) *)((uintptr_t)img->header + img->header->e_phoff);
  memcpy(phdr_copy, original_phdr, phdr_size);

  return phdr_copy;
}

bool register_custom_library_for_backtrace(ElfImg *img) {
  pthread_mutex_lock(&g_custom_libs_mutex);

  int slot = -1;
  for (int i = 0; i < MAX_CUSTOM_LIBS; i++) {
    if (g_custom_libs[i].in_use) continue;
    
    slot = i;

    break;
  }

  if (slot == -1) {
    pthread_mutex_unlock(&g_custom_libs_mutex);

    LOGE("No available slots for custom library registration");

    return false;
  }

  struct custom_lib_info *lib_info = &g_custom_libs[slot];
  lib_info->phdr_copy = copy_program_headers(img);
  if (!lib_info->phdr_copy) {
    pthread_mutex_unlock(&g_custom_libs_mutex);

    LOGE("Failed to copy program headers for custom library %s", img->elf);

    return false;
  }

  lib_info->phdr_info.dlpi_addr = (ElfW(Addr))img->base - img->bias;
  lib_info->phdr_info.dlpi_name = img->elf;
  lib_info->phdr_info.dlpi_phdr = lib_info->phdr_copy;
  lib_info->phdr_info.dlpi_phnum = img->header->e_phnum;
  lib_info->phdr_info.dlpi_adds = 1;
  lib_info->phdr_info.dlpi_subs = 0;

  if (img->tls_segment) {
    lib_info->phdr_info.dlpi_tls_modid = img->tls_mod_id;
    lib_info->phdr_info.dlpi_tls_data = NULL;
  } else {
    lib_info->phdr_info.dlpi_tls_modid = 0;
    lib_info->phdr_info.dlpi_tls_data = NULL;
  }

  lib_info->img = img;
  lib_info->in_use = true;
  lib_info->eh_frame_registered = NULL;
  lib_info->eh_frame_size = 0;

  pthread_mutex_unlock(&g_custom_libs_mutex);

  LOGD("Registered custom library %s for backtrace support", img->elf);

  return true;
}

bool unregister_custom_library_for_backtrace(ElfImg *img) {
  pthread_mutex_lock(&g_custom_libs_mutex);

  for (int i = 0; i < MAX_CUSTOM_LIBS; i++) {
    if (g_custom_libs[i].in_use && g_custom_libs[i].img != img) continue;

    if (g_custom_libs[i].eh_frame_registered) {
      __deregister_frame(g_custom_libs[i].eh_frame_registered);

      LOGD("Deregistered .eh_frame for %s", img->elf);

      g_custom_libs[i].eh_frame_registered = NULL;
    }

    if (g_custom_libs[i].phdr_copy) free(g_custom_libs[i].phdr_copy);
    memset(&g_custom_libs[i], 0, sizeof(struct custom_lib_info));

    pthread_mutex_unlock(&g_custom_libs_mutex);

    LOGD("Unregistered custom library for backtrace support");

    return true;
  }

  pthread_mutex_unlock(&g_custom_libs_mutex);

  return false;
}

void register_eh_frame_for_library(ElfImg *img) {
  #ifdef __arm__
    (void)img;

    LOGD("Skipping .eh_frame registration on ARM32 (EHABI)");

    return;
  #else
    void *eh_frame_ptr = NULL;
    size_t eh_frame_size = 0;
    if (locate_eh_frame_ptr(img, &eh_frame_ptr, &eh_frame_size) != 0 || !eh_frame_ptr) {
      LOGW("No .eh_frame found for %s; exceptions may fail", img->elf);

      return;
    }

    __register_frame(eh_frame_ptr);
    LOGD("Registered .eh_frame at %p (size ~%zu) for %s", eh_frame_ptr, eh_frame_size, img->elf);

    /* Store for deregistration */
    pthread_mutex_lock(&g_custom_libs_mutex);
    for (int i = 0; i < MAX_CUSTOM_LIBS; i++) {
      if (!g_custom_libs[i].in_use || g_custom_libs[i].img != img) continue;

      g_custom_libs[i].eh_frame_registered = eh_frame_ptr;
      g_custom_libs[i].eh_frame_size = eh_frame_size;

      break;
    }

    pthread_mutex_unlock(&g_custom_libs_mutex);
  #endif
}

void unregister_eh_frame_for_library(ElfImg *img) {
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