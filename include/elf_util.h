/* Copyright (c) 2025 ThePedroo. All rights reserved.
 *
 * This source code is licensed under the GNU AGPLv3 License found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef ELF_UTIL_H
#define ELF_UTIL_H

#include <stdbool.h>
#include <string.h>
#include <link.h>
#include <sys/types.h>
#include <pthread.h>
#include <stdint.h>

#define SHT_GNU_HASH 0x6ffffff6

typedef void (*linker_simple_func_t)(void);
typedef void (*linker_ctor_function_t)(int, char**, char**);
typedef void (*linker_dtor_function_t)(void);

struct symtabs {
  char *name;
  ElfW(Sym) *sym;
};

/* TODO: Use pure struct. This looks horrible. */
typedef struct {
  char *elf;
  void *base;
  ElfW(Ehdr) *header;
  size_t size;
  off_t bias;
  ElfW(Shdr) *section_header;

  ElfW(Shdr) *dynsym;
  ElfW(Off) dynsym_offset;
  ElfW(Sym) *dynsym_start;
  ElfW(Shdr) *strtab;
  ElfW(Off) symstr_offset;
  void *strtab_start;

  uint32_t nbucket_;
  uint32_t *bucket_;
  uint32_t *chain_;

  uint32_t gnu_nbucket_;
  uint32_t gnu_symndx_;
  uint32_t gnu_bloom_size_;
  uint32_t gnu_shift2_;
  uintptr_t *gnu_bloom_filter_;
  uint32_t *gnu_bucket_;
  uint32_t *gnu_chain_;

  ElfW(Shdr) *symtab;
  ElfW(Off) symtab_offset;
  size_t symtab_size;
  size_t symtab_count;
  ElfW(Sym) *symtab_start;
  ElfW(Off) symstr_offset_for_symtab;

  ElfW(Phdr) *tls_segment;
  size_t tls_mod_id;

  ElfW(Relr) *relr_;
  size_t relr_count_;

  struct symtabs *symtabs_;

  linker_ctor_function_t *preinit_array;
  size_t preinit_array_count;

  linker_ctor_function_t *init_array;
  size_t init_array_count;

  linker_dtor_function_t *fini_array;
  size_t fini_array_count;

  linker_simple_func_t preinit_func;
  linker_simple_func_t init_func;
  linker_simple_func_t fini_func;

  const uint8_t *eh_frame;
  size_t eh_frame_size;
  const uint8_t *eh_frame_hdr;
  size_t eh_frame_hdr_size;
  const uint8_t *gcc_except_table;
  size_t gcc_except_table_size;

  #ifdef __arm__
    const uint8_t *arm_exidx;
    size_t arm_exidx_count;
  #endif
} ElfImg;

struct sym_info {
  const char *name;
  ElfW(Addr) address;
};

void ElfImg_destroy(ElfImg *img);

void *get_library_base(const char *lib_path);

ElfImg *ElfImg_create(const char *elf, void *base);

ElfW(Addr) getSymbOffset(ElfImg *img, const char *name, unsigned char *sym_type);

ElfW(Addr) getSymbAddress(ElfImg *img, const char *name);

ElfW(Addr) getSymbAddressByPrefix(ElfImg *img, const char *prefix);

void *getSymbValueByPrefix(ElfImg *img, const char *prefix);

struct sym_info elf_get_symbol(ElfImg *img, uintptr_t addr);

#endif /* ELF_UTIL_H */
