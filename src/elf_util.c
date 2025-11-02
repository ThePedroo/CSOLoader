/* Copyright (c) 2025 ThePedroo. All rights reserved.
 *
 * This source code is licensed under the GNU AGPLv3 License found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/auxv.h>

#include <unistd.h>

#include "logging.h"

#include "elf_util.h"

#define SHT_GNU_HASH 0x6ffffff6

#ifndef ELF_ST_TYPE
  #ifdef __LP64__
    #define ELF_ST_TYPE ELF64_ST_TYPE
  #else
    #define ELF_ST_TYPE ELF32_ST_TYPE
  #endif
#endif

#ifndef ELF_ST_BIND
  #ifdef __LP64__
    #define ELF_ST_BIND ELF64_ST_BIND
  #else
    #define ELF_ST_BIND ELF32_ST_BIND
  #endif
#endif

uint32_t ElfHash(const char *name) {
  uint32_t h = 0, g = 0;

  while (*name) {
    h = (h << 4) + (unsigned char)*name++;
    g = h & 0xf0000000;

    if (g) {
      h ^= g >> 24;
    }

    h &= ~g;
  }

  return h;
}

uint32_t GnuHash(const char *name) {
  uint32_t h = 5381;

  while (*name) {
    h = (h << 5) + h + (unsigned char)(*name++);
  }

  return h;
}

ElfW(Shdr) *offsetOf_Shdr(ElfW(Ehdr) *head, ElfW(Off) off) {
  return (ElfW(Shdr) *)(((uintptr_t)head) + off);
}

char *offsetOf_char(ElfW(Ehdr) *head, ElfW(Off) off) {
  return (char *)(((uintptr_t)head) + off);
}

ElfW(Sym) *offsetOf_Sym(ElfW(Ehdr) *head, ElfW(Off) off) {
  return (ElfW(Sym) *)(((uintptr_t)head) + off);
}

ElfW(Word) *offsetOf_Word(ElfW(Ehdr) *head, ElfW(Off) off) {
  return (ElfW(Word) *)(((uintptr_t)head) + off);
}

int dl_cb(struct dl_phdr_info *info, size_t size, void *data) {
  (void) size;

  if (info->dlpi_name == NULL)
    return 0;

  ElfImg *img = (ElfImg *)data;

  if (strstr(info->dlpi_name, img->elf)) {
    img->base = (void *)info->dlpi_addr;

    return 1;
  }

  return 0;
}

bool _find_module_base(ElfImg *img) {
  dl_iterate_phdr(dl_cb, img);

  return img->base != NULL;
}

size_t calculate_valid_symtabs_amount(ElfImg *img) {
  size_t count = 0;

  if (img->symtab_start == NULL || img->symstr_offset_for_symtab == 0) {
    LOGE("Invalid symtab_start or symstr_offset_for_symtab, cannot count valid symbols");

    return 0;
  }

  char *symtab_strings = offsetOf_char(img->header, img->symstr_offset_for_symtab);

  for (ElfW(Off) i = 0; i < img->symtab_count; i++) {
    const char *sym_name = symtab_strings + img->symtab_start[i].st_name;
    if (!sym_name)
      continue;

    unsigned int st_type = ELF_ST_TYPE(img->symtab_start[i].st_info);

    if ((st_type == STT_FUNC || st_type == STT_OBJECT) && img->symtab_start[i].st_size > 0 && img->symtab_start[i].st_name != 0)
      count++;
  }

  return count;
}

void ElfImg_destroy(ElfImg *img) {
  if (!img) return;

  if (img->symtabs_) {
    size_t valid_symtabs_amount = calculate_valid_symtabs_amount(img);
    if (valid_symtabs_amount > 0) {
      for (size_t i = 0; i < valid_symtabs_amount; i++) {
        free(img->symtabs_[i].name);
      }
    }

    free(img->symtabs_);
    img->symtabs_ = NULL;
  }

  if (img->elf) {
    free(img->elf);
    img->elf = NULL;
  }

  if (img->header) {
    munmap(img->header, img->size);
    img->header = NULL;
  }

  free(img);
}

ElfImg *ElfImg_create(const char *elf, void *base) {
  ElfImg *img = (ElfImg *)calloc(1, sizeof(ElfImg));
  if (!img) {
    LOGE("Failed to allocate memory for ElfImg");

    return NULL;
  }

  img->elf = strdup(elf);
  if (!img->elf) {
    LOGE("Failed to duplicate elf path string");

    free(img);

    return NULL;
  }

  if (base) {
    /* INFO: Due to the use in zygisk-ptracer, we need to allow pre-
              fetched bases to be passed, as the linker (Android 7.1
              and below) is not loaded from dlopen, which makes it not
              be visible with dl_iterate_phdr.
    */
    img->base = base;

    LOGD("Using provided base address 0x%p for %s", base, elf);
  } else {
    if (!_find_module_base(img)) {
      LOGE("Failed to find module base for %s using dl_iterate_phdr", elf);

      ElfImg_destroy(img);

      return NULL;
    }
  }

  int fd = open(elf, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    LOGE("failed to open %s", elf);

    ElfImg_destroy(img);

    return NULL;
  }

  struct stat st;
  if (fstat(fd, &st) != 0) {
    LOGE("fstat() failed for %s", elf);

    close(fd);
    ElfImg_destroy(img);

    return NULL;
  }

  img->size = st.st_size;

  if (img->size <= sizeof(ElfW(Ehdr))) {
    LOGE("Invalid file size %zu for %s", img->size, elf);

    close(fd);
    ElfImg_destroy(img);

    return NULL;
  }

  img->header = (ElfW(Ehdr) *)mmap(NULL, img->size, PROT_READ, MAP_PRIVATE, fd, 0);

  close(fd);

  if (img->header == MAP_FAILED) {
    LOGE("mmap() failed for %s", elf);

    img->header = NULL;
    ElfImg_destroy(img);

    return NULL;
  }

  if (memcmp(img->header->e_ident, ELFMAG, SELFMAG) != 0) {
    LOGE("Invalid ELF header for %s", elf);

    ElfImg_destroy(img);

    return NULL;
  }

  if (img->header->e_shoff == 0 || img->header->e_shentsize == 0 || img->header->e_shnum == 0) {
    LOGW("Section header table missing or invalid in %s", elf);
  } else {
    img->section_header = offsetOf_Shdr(img->header, img->header->e_shoff);
  }

  if (img->header->e_phoff == 0 || img->header->e_phentsize == 0 || img->header->e_phnum == 0) {
    LOGW("Program header table missing or invalid in %s", elf);
  }

  ElfW(Shdr) *dynsym_shdr = NULL;
  ElfW(Shdr) *symtab_shdr = NULL;

  char *section_str = NULL;
  if (img->section_header && img->header->e_shstrndx != SHN_UNDEF) {
    if (img->header->e_shstrndx < img->header->e_shnum) {
      ElfW(Shdr) *shstrtab_hdr = img->section_header + img->header->e_shstrndx;
      section_str = offsetOf_char(img->header, shstrtab_hdr->sh_offset);
    } else {
      LOGW("Section header string table index (%u) out of bounds (%u)", img->header->e_shstrndx, img->header->e_shnum);
    }
  } else {
    LOGW("Section header string table index not set or no section headers");
  }

  if (img->section_header) {
    uintptr_t shoff = (uintptr_t)img->section_header;
    for (int i = 0; i < img->header->e_shnum; i++, shoff += img->header->e_shentsize) {
      ElfW(Shdr) *section_h = (ElfW(Shdr *))shoff;
      char *sname = section_str ? (section_h->sh_name + section_str) : "<?>";
      size_t entsize = section_h->sh_entsize;

      switch (section_h->sh_type) {
        case SHT_DYNSYM: {
          dynsym_shdr = section_h;
          img->dynsym_offset = section_h->sh_offset;
          img->dynsym_start = offsetOf_Sym(img->header, img->dynsym_offset);

          break;
        }
        case SHT_SYMTAB: {
          if (strcmp(sname, ".symtab") == 0) {
            symtab_shdr = section_h;
            img->symtab_offset = section_h->sh_offset;
            img->symtab_size = section_h->sh_size;

            if (entsize > 0) img->symtab_count = img->symtab_size / entsize;
            else {
              LOGW("Section %s has zero sh_entsize", sname);
              img->symtab_count = 0;
            }

            img->symtab_start = offsetOf_Sym(img->header, img->symtab_offset);
          }

          break;
        }
        case SHT_STRTAB: break;
        case SHT_PROGBITS: break;
        case SHT_HASH: {
          ElfW(Word) *d_un = offsetOf_Word(img->header, section_h->sh_offset);

          if (section_h->sh_size >= 2 * sizeof(ElfW(Word))) {
            img->nbucket_ = d_un[0];

            if (img->nbucket_ > 0 && section_h->sh_size >= (2 + img->nbucket_ + d_un[1]) * sizeof(ElfW(Word))) {
              img->bucket_ = d_un + 2;
              img->chain_ = img->bucket_ + img->nbucket_;
            } else {
              LOGW("Invalid SHT_HASH size or nbucket count in section %s", sname);
              img->nbucket_ = 0;
            }
          } else {
            LOGW("SHT_HASH section %s too small", sname);
          }

          break;
        }
        case SHT_GNU_HASH: {
          ElfW(Word) *d_buf = offsetOf_Word(img->header, section_h->sh_offset);

          if (section_h->sh_size >= 4 * sizeof(ElfW(Word))) {
            img->gnu_nbucket_ = d_buf[0];
            img->gnu_symndx_ = d_buf[1];
            img->gnu_bloom_size_ = d_buf[2];
            img->gnu_shift2_ = d_buf[3];

            size_t expected_min_size = 4 * sizeof(ElfW(Word)) +
                                      img->gnu_bloom_size_ * sizeof(uintptr_t) +
                                      img->gnu_nbucket_ * sizeof(uint32_t);

            if (img->gnu_nbucket_ > 0 && img->gnu_bloom_size_ > 0 && section_h->sh_size >= expected_min_size) {
              img->gnu_bloom_filter_ = (uintptr_t *)(d_buf + 4);
              img->gnu_bucket_ = (uint32_t *)(img->gnu_bloom_filter_ + img->gnu_bloom_size_);
              img->gnu_chain_ = img->gnu_bucket_ + img->gnu_nbucket_;

              uintptr_t chain_start_offset = (uintptr_t)img->gnu_chain_ - (uintptr_t)img->header;
              if (chain_start_offset < section_h->sh_offset || chain_start_offset >= section_h->sh_offset + section_h->sh_size) {
                LOGW("Calculated GNU hash chain seems out of bounds for section %s", sname);

                img->gnu_nbucket_ = 0;
              }
            } else {
              LOGW("Invalid SHT_GNU_HASH size or parameters in section %s", sname);

              img->gnu_nbucket_ = 0;
            }
          } else {
            LOGW("SHT_GNU_HASH section %s too small", sname);
          }

          break;
        }
      }
    }
  }

  ElfW(Shdr) *shdr_base = img->section_header;

  if (dynsym_shdr && shdr_base) {
    img->dynsym = dynsym_shdr;

    if (dynsym_shdr->sh_link < img->header->e_shnum) {
      ElfW(Shdr) *linked_strtab = shdr_base + dynsym_shdr->sh_link;

      if (linked_strtab->sh_type == SHT_STRTAB) {
        img->strtab = linked_strtab;
        img->symstr_offset = linked_strtab->sh_offset;
        img->strtab_start = (void *)offsetOf_char(img->header, img->symstr_offset);
      } else {
        LOGW("Section %u linked by .dynsym is not SHT_STRTAB (type %u)", dynsym_shdr->sh_link, linked_strtab->sh_type);
      }
    } else {
      LOGE(".dynsym sh_link (%u) is out of bounds (%u)", dynsym_shdr->sh_link, img->header->e_shnum);
    }
  } else {
    LOGW("No .dynsym section found or section headers missing");
  }

  if (symtab_shdr && shdr_base) {
    img->symtab = symtab_shdr;

    if (symtab_shdr->sh_link < img->header->e_shnum) {
      ElfW(Shdr) *linked_strtab = shdr_base + symtab_shdr->sh_link;

      if (linked_strtab->sh_type == SHT_STRTAB) {
        /* INFO: For linear lookup */
        img->symstr_offset_for_symtab = linked_strtab->sh_offset;
      } else {
        LOGW("Section %u linked by .symtab is not SHT_STRTAB (type %u)", symtab_shdr->sh_link, linked_strtab->sh_type);

        img->symstr_offset_for_symtab = 0;
      }
    } else {
      LOGE(".symtab sh_link (%u) is out of bounds (%u)", symtab_shdr->sh_link, img->header->e_shnum);

      img->symstr_offset_for_symtab = 0;
    }
  } else {
    LOGD("No .symtab section found or section headers missing");

    img->symtab_start = NULL;
    img->symtab_count = 0;
    img->symstr_offset_for_symtab = 0;
  }

  /* TODO: Maybe better to use memset? */
  img->eh_frame = NULL;
  img->eh_frame_size = 0;
  img->eh_frame_hdr = NULL;
  img->eh_frame_hdr_size = 0;
  img->gcc_except_table = NULL;
  img->gcc_except_table_size = 0;
  #ifdef __arm__
    img->arm_exidx = NULL;
    img->arm_exidx_count = 0;
  #endif

  bool bias_calculated = false;
  if (img->header->e_phoff > 0 && img->header->e_phnum > 0) {
    ElfW(Phdr) *phdr = (ElfW(Phdr) *)((uintptr_t)img->header + img->header->e_phoff);
    ElfW(Dyn) *dyn = NULL;

    for (int i = 0; i < img->header->e_phnum; ++i) {
      if (phdr[i].p_type == PT_DYNAMIC) {
        dyn = (ElfW(Dyn) *)((uintptr_t)img->base + phdr[i].p_vaddr - img->bias);

        LOGD("Located PT_DYNAMIC segment at virtual address: 0x%llu", (unsigned long long)phdr[i].p_vaddr);
      }

      if (phdr[i].p_type == PT_TLS) {
        img->tls_segment = &phdr[i];

        LOGD("Found TLS segment at %d in %s", i, elf);
      }

      if (phdr[i].p_type == PT_LOAD && phdr[i].p_offset == 0) {
        img->bias = phdr[i].p_vaddr - phdr[i].p_offset;
        bias_calculated = true;

        LOGD("Calculated bias %ld from PT_LOAD segment %d (vaddr %lx)", (long)img->bias, i, (unsigned long)phdr[i].p_vaddr);
      }
    }

    if (dyn) for (ElfW(Dyn) *d = dyn; d->d_tag != DT_NULL; ++d) {
      uintptr_t ptr_val = (uintptr_t)img->base + d->d_un.d_ptr - img->bias;
      switch (d->d_tag) {
        case DT_INIT: {
          img->init_func = (linker_simple_func_t)ptr_val;

          LOGD("Found DT_INIT for %s at %p", img->elf, img->init_func);

          break;
        }
        case DT_FINI: {
          img->fini_func = (linker_simple_func_t)ptr_val;

          LOGD("Found DT_FINI for %s at %p", img->elf, img->fini_func);

          break;
        }
        case DT_PREINIT_ARRAY: {
          img->preinit_array = (linker_ctor_function_t *)ptr_val;

          LOGD("Found DT_PREINIT_ARRAY for %s at %p", img->elf, img->preinit_array);

          break;
        }
        case DT_PREINIT_ARRAYSZ: {
          img->preinit_array_count = d->d_un.d_val / sizeof(ElfW(Addr));

          LOGD("Found DT_PREINIT_ARRAYSZ for %s: %zu entries", img->elf, img->preinit_array_count);

          break;
        }
        case DT_INIT_ARRAY: {
          img->init_array = (linker_ctor_function_t *)ptr_val;

          LOGD("Found DT_INIT_ARRAY for %s at %p", img->elf, img->init_array);

          break;
        }
        case DT_INIT_ARRAYSZ: {
          img->init_array_count = d->d_un.d_val / sizeof(ElfW(Addr));

          LOGD("Found DT_INIT_ARRAYSZ for %s: %zu entries", img->elf, img->init_array_count);

          break;
        }
        case DT_FINI_ARRAY: {
          img->fini_array = (linker_dtor_function_t *)ptr_val;

          LOGD("Found DT_FINI_ARRAY for %s at %p", img->elf, img->fini_array);

          break;
        }
        case DT_FINI_ARRAYSZ: {
          img->fini_array_count = d->d_un.d_val / sizeof(linker_dtor_function_t);

          LOGD("Found DT_FINI_ARRAYSZ for %s: %zu entries", img->elf, img->fini_array_count);

          break;
        }
        case DT_RELR:
        #ifdef __ANDROID__
        case DT_ANDROID_RELR:
        #endif
          img->relr_ = (ElfW(Relr) *)(img->bias + d->d_un.d_ptr);

          LOGD("Found DT_RELR/DT_ANDROID_RELR for %s at %p", img->elf, img->relr_);

          break;
        case DT_RELRSZ:
        #ifdef __ANDROID__
        case DT_ANDROID_RELRSZ:
        #endif
          img->relr_count_ = d->d_un.d_val / sizeof(ElfW(Relr));

          LOGD("Found DT_RELRSZ/DT_ANDROID_RELRSZ for %s: %zu entries", img->elf, img->relr_count_);

          break;
        case DT_RELRENT:
        #ifdef __ANDROID__
        case DT_ANDROID_RELRENT:
        #endif
          LOGD("Found DT_RELRENT/DT_ANDROID_RELRENT for %s", img->elf);

          if (d->d_un.d_val != sizeof(ElfW(Relr)))
            LOGF("invalid DT_RELRENT: %zd", (size_t)d->d_un.d_val);

          break;
      }
    }

    if (!bias_calculated) for (int i = 0; i < img->header->e_phnum; ++i) {
      if (phdr[i].p_type != PT_LOAD) continue;

      img->bias = phdr[i].p_vaddr - phdr[i].p_offset;
      bias_calculated = true;

      LOGD("Calculated bias %ld from first PT_LOAD segment %d (vaddr %lx, offset %lx)",
          (long)img->bias, i, (unsigned long)phdr[i].p_vaddr, (unsigned long)phdr[i].p_offset);

      break;
    }

    /* INFO: Populate EH regions from Program Headers when possible */
    for (int i = 0; i < img->header->e_phnum; ++i) {
      if (phdr[i].p_type == PT_GNU_EH_FRAME) {
        img->eh_frame_hdr = (const uint8_t *)((uintptr_t)img->base + phdr[i].p_vaddr - img->bias);
        img->eh_frame_hdr_size = phdr[i].p_memsz;

        LOGD("Found PT_GNU_EH_FRAME for %s at %p (size %zu)", img->elf, img->eh_frame_hdr, img->eh_frame_hdr_size);
      }

      #ifdef __arm__
        if (phdr[i].p_type == PT_ARM_EXIDX) {
          img->arm_exidx = (const uint8_t *)((uintptr_t)img->base + phdr[i].p_vaddr - img->bias);
          img->arm_exidx_count = phdr[i].p_memsz / 8;

          LOGD("Found PT_ARM_EXIDX for %s at %p (entries %zu)", img->elf, img->arm_exidx, img->arm_exidx_count);
        }
      #endif
    }
  }

  if (!bias_calculated)
    LOGE("Failed to calculate bias for %s. Assuming bias is 0.", elf);

  if (!img->dynsym_start || !img->strtab_start) {
    if (img->header->e_type == ET_DYN) LOGE("Failed to find .dynsym or its string table (.dynstr) in %s", elf);
    else LOGW("No .dynsym or .dynstr found in %s (might be expected for ET_EXEC)", elf);
  }

  if (!img->gnu_bucket_ && !img->bucket_)
    LOGW("No hash table (.gnu.hash or .hash) found in %s. Dynamic symbol lookup might be slow or fail.", elf);

  /* INFO: Populate EH regions from Section Headers */
  if (img->section_header && img->header->e_shstrndx != SHN_UNDEF && img->header->e_shstrndx < img->header->e_shnum) {
    ElfW(Shdr) *shstrtab_hdr = img->section_header + img->header->e_shstrndx;
    char *sec_names = offsetOf_char(img->header, shstrtab_hdr->sh_offset);

    for (int i = 0; i < img->header->e_shnum; i++) {
      ElfW(Shdr) *sh = img->section_header + i;
      const char *sname = sec_names ? (sec_names + sh->sh_name) : NULL;
      if (!sname) continue;

      if (strcmp(sname, ".eh_frame") == 0) {
        img->eh_frame = (const uint8_t *)((uintptr_t)img->base + sh->sh_addr - img->bias);
        img->eh_frame_size = sh->sh_size;

        LOGD("Section .eh_frame at %p (size %zu) for %s", img->eh_frame, img->eh_frame_size, img->elf);
      } else if (strcmp(sname, ".eh_frame_hdr") == 0) {
        img->eh_frame_hdr = (const uint8_t *)((uintptr_t)img->base + sh->sh_addr - img->bias);
        img->eh_frame_hdr_size = sh->sh_size;

        LOGD("Section .eh_frame_hdr at %p (size %zu) for %s", img->eh_frame_hdr, img->eh_frame_hdr_size, img->elf);
      } else if (strcmp(sname, ".gcc_except_table") == 0) {
        img->gcc_except_table = (const uint8_t *)((uintptr_t)img->base + sh->sh_addr - img->bias);
        img->gcc_except_table_size = sh->sh_size;

        LOGD("Section .gcc_except_table at %p (size %zu) for %s", img->gcc_except_table, img->gcc_except_table_size, img->elf);
      }
      #ifdef __arm__
        else if (strcmp(sname, ".ARM.exidx") == 0) {
          img->arm_exidx = (const uint8_t *)((uintptr_t)img->base + sh->sh_addr - img->bias);
          img->arm_exidx_count = sh->sh_size / 8;

          LOGD("Section .ARM.exidx at %p (entries %zu) for %s", img->arm_exidx, img->arm_exidx_count, img->elf);
        }
      #endif
    }
  }

  return img;
}

bool _load_symtabs(ElfImg *img) {
  if (img->symtabs_) return true;

  if (!img->symtab_start || img->symstr_offset_for_symtab == 0 || img->symtab_count == 0) {
    // LOGE("Cannot load symtabs: .symtab section or its string table not found/valid.");

    return false;
  }

  size_t valid_symtabs_amount = calculate_valid_symtabs_amount(img);
  if (valid_symtabs_amount == 0) {
    LOGW("No valid symbols (FUNC/OBJECT with size > 0) found in .symtab for %s", img->elf);

    return false;
  }

  img->symtabs_ = (struct symtabs *)calloc(valid_symtabs_amount, sizeof(struct symtabs));
  if (!img->symtabs_) {
    LOGE("Failed to allocate memory for symtabs array");

    return false;
  }

  char *symtab_strings = offsetOf_char(img->header, img->symstr_offset_for_symtab);
  size_t current_valid_index = 0;

  for (ElfW(Off) pos = 0; pos < img->symtab_count; pos++) {
    ElfW(Sym) *current_sym = &img->symtab_start[pos];
    unsigned int st_type = ELF_ST_TYPE(current_sym->st_info);

    if ((st_type == STT_FUNC || st_type == STT_OBJECT) && current_sym->st_size > 0 && current_sym->st_name != 0) {
      const char *st_name = symtab_strings + current_sym->st_name;
      if (!st_name)
        continue;

      ElfW(Shdr) *symtab_str_shdr = img->section_header + img->symtab->sh_link;
      if (current_sym->st_name >= symtab_str_shdr->sh_size) {
        LOGE("Symbol name offset out of bounds");

        continue;
      }

      img->symtabs_[current_valid_index].name = strdup(st_name);
      if (!img->symtabs_[current_valid_index].name) {
        LOGE("Failed to duplicate symbol name: %s", st_name);

        for(size_t k = 0; k < current_valid_index; ++k) {
          free(img->symtabs_[k].name);
        }

        free(img->symtabs_);
        img->symtabs_ = NULL;

        return false;
      }

      img->symtabs_[current_valid_index].sym = current_sym;

      current_valid_index++;
      if (current_valid_index == valid_symtabs_amount) break;
    }
  }

  return true;
}

ElfW(Addr) GnuLookup(ElfImg *restrict img, const char *name, uint32_t hash, unsigned char *sym_type) {
  if (img->gnu_nbucket_ == 0 || img->gnu_bloom_size_ == 0 || !img->gnu_bloom_filter_ || !img->gnu_bucket_ || !img->gnu_chain_ || !img->dynsym_start || !img->strtab_start)
    return 0;

  static const size_t bloom_mask_bits = sizeof(uintptr_t) * 8;

  size_t bloom_idx = (hash / bloom_mask_bits) % img->gnu_bloom_size_;
  uintptr_t bloom_word = img->gnu_bloom_filter_[bloom_idx];
  uintptr_t mask = ((uintptr_t)1 << (hash % bloom_mask_bits)) |
                   ((uintptr_t)1 << ((hash >> img->gnu_shift2_) % bloom_mask_bits));

  if ((mask & bloom_word) != mask) {
    /* INFO: Very loggy -- generates too much noise. GNU is rarely used for Zygisk context. */
    /* LOGW("Symbol '%s' (hash %u) filtered out by GNU Bloom Filter (idx %zu, mask 0x%lx, word 0x%lx)",
           name, hash, bloom_idx, (unsigned long)mask, (unsigned long)bloom_word);
    */

    return 0;
  }

  uint32_t sym_index = img->gnu_bucket_[hash % img->gnu_nbucket_];
  if (sym_index < img->gnu_symndx_) {
    LOGW("Symbol %s hash %u maps to bucket %u index %u (below gnu_symndx %u), not exported?", name, hash, hash % img->gnu_nbucket_, sym_index, img->gnu_symndx_);

    return 0;
  }

  char *strings = (char *)img->strtab_start;
  uint32_t chain_val = img->gnu_chain_[sym_index - img->gnu_symndx_];

  ElfW(Word) dynsym_count = img->dynsym->sh_size / img->dynsym->sh_entsize;
  if (sym_index >= dynsym_count) {
    LOGE("Symbol index %u out of bounds", sym_index);

    return 0;
  }

  ElfW(Sym) *sym = img->dynsym_start + sym_index;

  if (sym->st_name >= img->strtab->sh_size) {
    LOGE("Symbol name offset %u out of bounds", sym->st_name);

    return 0;
  }

  if ((((chain_val ^ hash) >> 1) == 0 && strcmp(name, strings + sym->st_name) == 0) && sym->st_shndx != SHN_UNDEF) {
    unsigned int type = ELF_ST_TYPE(sym->st_info);
    if (sym_type) *sym_type = type;

    return sym->st_value;
  }

  while ((chain_val & 1) == 0) {
    sym_index++;

    if (sym_index >= dynsym_count) {
      LOGE("Symbol index %u out of bounds during chain walk", sym_index);

      return 0;
    }

    chain_val = img->gnu_chain_[sym_index - img->gnu_symndx_];
    sym = img->dynsym_start + sym_index;

    if (sym->st_name >= img->strtab->sh_size) {
      LOGE("Symbol name offset %u out of bounds", sym->st_name);

      break;
    }

    if ((((chain_val ^ hash) >> 1) == 0 && strcmp(name, strings + sym->st_name) == 0) && sym->st_shndx != SHN_UNDEF) {
      unsigned int type = ELF_ST_TYPE(sym->st_info);
      if (sym_type) *sym_type = type;

      return sym->st_value;
    }
  }

  return 0;
}

ElfW(Addr) ElfLookup(ElfImg *restrict img, const char *restrict name, uint32_t hash, unsigned char *sym_type) {
  if (img->nbucket_ == 0 || !img->bucket_ || !img->chain_ || !img->dynsym_start || !img->strtab_start)
    return 0;

  char *strings = (char *)img->strtab_start;

  for (size_t n = img->bucket_[hash % img->nbucket_]; n != STN_UNDEF; n = img->chain_[n]) {
    ElfW(Sym) *sym = img->dynsym_start + n;

    if (strcmp(name, strings + sym->st_name) == 0 && sym->st_shndx != SHN_UNDEF) {
      unsigned int type = ELF_ST_TYPE(sym->st_info);
      if (sym_type) *sym_type = type;

      return sym->st_value;
    }
  }

  return 0;
}

bool _load_symtabs(ElfImg *img);

ElfW(Addr) LinearLookup(ElfImg *img, const char *restrict name, unsigned char *sym_type) {
  if (!_load_symtabs(img)) {
    // LOGE("Failed to load symtabs for linear lookup of %s", name);

    return 0;
  }

  size_t valid_symtabs_amount = calculate_valid_symtabs_amount(img);
  if (valid_symtabs_amount == 0) {
    LOGW("No valid symbols (FUNC/OBJECT with size > 0) found in .symtab for %s", img->elf);

    return 0;
  }

  for (size_t i = 0; i < valid_symtabs_amount; i++) {
    if (!img->symtabs_[i].name || strcmp(name, img->symtabs_[i].name) != 0)
      continue;

    if (img->symtabs_[i].sym->st_shndx == SHN_UNDEF)
      continue;

    unsigned int type = ELF_ST_TYPE(img->symtabs_[i].sym->st_info);
    if (sym_type) *sym_type = type;

    return img->symtabs_[i].sym->st_value;
  }

  return 0;
}

ElfW(Addr) LinearLookupByPrefix(ElfImg *img, const char *prefix, unsigned char *sym_type) {
  if (!_load_symtabs(img)) {
    LOGE("Failed to load symtabs for linear lookup by prefix of %s", prefix);

    return 0;
  }

  size_t valid_symtabs_amount = calculate_valid_symtabs_amount(img);
  if (valid_symtabs_amount == 0) {
    LOGW("No valid symbols (FUNC/OBJECT with size > 0) found in .symtab for %s", img->elf);

    return 0;
  }

  size_t prefix_len = strlen(prefix);
  if (prefix_len == 0) return 0;

  for (size_t i = 0; i < valid_symtabs_amount; i++) {
    if (!img->symtabs_[i].name || strlen(img->symtabs_[i].name) < prefix_len)
      continue;

    if (strncmp(img->symtabs_[i].name, prefix, prefix_len) != 0)
      continue;

    if (img->symtabs_[i].sym->st_shndx == SHN_UNDEF)
      continue;

    unsigned int type = ELF_ST_TYPE(img->symtabs_[i].sym->st_info);
    if (sym_type) *sym_type = type;

    return img->symtabs_[i].sym->st_value;
  }

  return 0;
}

ElfW(Addr) getSymbOffset(ElfImg *img, const char *name, unsigned char *sym_type) {
  ElfW(Addr) offset = 0;

  offset = GnuLookup(img, name, GnuHash(name), sym_type);
  if (offset != 0) return offset;

  offset = ElfLookup(img, name, ElfHash(name), sym_type);
  if (offset != 0) return offset;

  offset = LinearLookup(img, name, sym_type);
  if (offset != 0) return offset;

  return 0;
}

#ifdef __aarch64__
  struct __ifunc_arg_t {
    unsigned long _size;
    unsigned long _hwcap;
    unsigned long _hwcap2;
  };
  #define _IFUNC_ARG_HWCAP (1ULL << 62)
#elif defined(__riscv)
  struct riscv_hwprobe {
    int64_t key;
    uint64_t value;
  };
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
  typedef int (*__riscv_hwprobe_t)(struct riscv_hwprobe *__pairs, size_t __pair_count, size_t __cpu_count, unsigned long *__cpus, unsigned __flags);
#endif

static ElfW(Addr) handle_indirect_symbol(ElfImg *img, ElfW(Off) offset) {
  ElfW(Addr) resolver_addr = (ElfW(Addr))((uintptr_t)img->base + offset - img->bias);

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

ElfW(Addr) getSymbAddress(ElfImg *img, const char *name) {
  unsigned char sym_type = 0;
  ElfW(Addr) offset = getSymbOffset(img, name, &sym_type);

  if (offset == 0 || !img->base) return 0;

  if (sym_type == STT_GNU_IFUNC) {
    LOGD("Resolving STT_GNU_IFUNC symbol %s", name);

    return handle_indirect_symbol(img, offset);
  }

  return (ElfW(Addr))((uintptr_t)img->base + offset - img->bias);
}

ElfW(Addr) getSymbAddressByPrefix(ElfImg *img, const char *prefix) {
  unsigned char sym_type = 0;
  ElfW(Addr) offset = LinearLookupByPrefix(img, prefix, &sym_type);

  if (offset == 0 || !img->base) return 0;

  if (sym_type == STT_GNU_IFUNC) {
    LOGD("Resolving STT_GNU_IFUNC symbol by prefix %s", prefix);

    return handle_indirect_symbol(img, offset);
  }

  return (ElfW(Addr))((uintptr_t)img->base + offset - img->bias);
}

void *getSymbValueByPrefix(ElfImg *img, const char *prefix) {
  ElfW(Addr) address = getSymbAddressByPrefix(img, prefix);

  return address == 0 ? NULL : *((void **)address);
}

struct sym_info elf_get_symbol(ElfImg *img, uintptr_t addr) {
  if (!_load_symtabs(img)) {
    return (struct sym_info){ .name = NULL, .address = 0 };
  }

  size_t valid_symtabs_amount = calculate_valid_symtabs_amount(img);
  if (valid_symtabs_amount == 0) {
    return (struct sym_info){ .name = NULL, .address = 0 };
  }

  for (size_t i = 0; i < valid_symtabs_amount; i++) {
    ElfW(Sym) *sym = img->symtabs_[i].sym;

    if (sym->st_value == 0 || sym->st_size == 0) {
      continue;
    }

    ElfW(Addr) sym_start = (ElfW(Addr))((uintptr_t)img->base + sym->st_value - img->bias);
    ElfW(Addr) sym_end = sym_start + sym->st_size;

    if (addr >= sym_start && addr < sym_end) {
      return (struct sym_info){ .name = img->symtabs_[i].name, .address = sym_start };
    }
  }

  return (struct sym_info){ .name = NULL, .address = 0 };
}
