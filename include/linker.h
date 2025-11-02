/* Copyright (c) 2025 ThePedroo. All rights reserved.
 *
 * This source code is licensed under the GNU AGPLv3 License found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef LINKER_H
#define LINKER_H

#include <elf.h>
#include <stdbool.h>

#include "elf_util.h"

#define MAX_DEPS 64

struct loaded_dep {
  ElfImg *img;
  bool is_manual_load;
  ElfW(Addr) file_vaddr_base;

  uintptr_t load_bias;
};

struct linker {
  ElfImg *img;
  struct loaded_dep dependencies[MAX_DEPS];

  int dep_count;
  bool is_linked;
};

void *linker_load_library_manually(const char *lib_path, struct loaded_dep *dep_info);

bool linker_init(struct linker *linker, ElfImg *img);

void linker_destroy(struct linker *linker);

bool linker_link(struct linker *linker);

#endif /* LINKER_H */
