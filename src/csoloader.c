/* Copyright (c) 2025 ThePedroo. All rights reserved.
 *
 * This source code is licensed under the GNU AGPLv3 License found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <elf.h>
#include <link.h>
#include <dlfcn.h>

#include "elf_util.h"
#include "linker.h"
#include "logging.h"

/* INFO: Global variables for argument passing */
extern int g_argc;
extern char **g_argv;
extern char **g_envp;

struct csoloader {
  char *lib_path;
  ElfImg *img;
  struct linker linker;
};

bool csoloader_load(struct csoloader *lib, const char *lib_path) {
  struct loaded_dep dep_info;
  void *map_start = linker_load_library_manually(lib_path, &dep_info);
  if (!map_start) {
    LOGE("Failed to load library: %s", lib_path);

    return false;
  }

  ElfImg *elf_image = ElfImg_create(lib_path, (void *)dep_info.load_bias);
  if (!elf_image) {
    LOGE("Failed to create ELF image for %s", lib_path);

    munmap(map_start, elf_image->size);

    return false;
  }

  struct linker linker;
  if (!linker_init(&linker, elf_image)) {
    LOGE("Failed to initialize linker for %s", lib_path);

    munmap(map_start, elf_image->size);
    ElfImg_destroy(elf_image);

    return false;
  }

  if (!linker_link(&linker)) {
    LOGE("Linker failed to link %s", lib_path);

    munmap(map_start, elf_image->size);
    ElfImg_destroy(elf_image);

    return false;
  }

  lib->img = elf_image;
  lib->lib_path = strdup(lib_path);
  if (!lib->lib_path) {
    LOGE("Failed to duplicate library path string");

    linker_destroy(&linker);
    ElfImg_destroy(elf_image);
    munmap(map_start, elf_image->size);

    return false;
  }
  lib->linker = linker;

  return true;
}

bool csoloader_unload(struct csoloader *lib) {
  /* INFO: Linker needs to deinit constructors. Munmap later. */
  linker_destroy(&lib->linker);
  munmap(lib->img->base, lib->img->size);
  ElfImg_destroy(lib->img);

  free(lib->lib_path);
  lib->lib_path = NULL;

  return true;
}

int main(int argc, char *argv[], char *envp[]) {
  LOGD("CSOLoader. Proprietary and confidential software. Copyright (c) 2025 by ThePedroo. All rights reserved.");

  /* INFO: Constructors need these */
  g_argc = argc;
  g_argv = argv;
  g_envp = envp;

  if (argc < 2) {
    LOGE("Usage: %s <library_path>", argv[0]);

    return EXIT_FAILURE;
  }

  const char *lib_path = argv[1];

  struct csoloader lib;
  if (!csoloader_load(&lib, lib_path)) {
    LOGE("Failed to load library: %s", lib_path);

    return EXIT_FAILURE;
  }

  const char *symbol_name = "shared_function";
  ElfW(Addr) sym_addr = getSymbAddress(lib.img, symbol_name);
  if (sym_addr == 0) sym_addr = getSymbAddress(lib.img, "_Z15shared_functionv");

  if (sym_addr == 0) {
    LOGE("Symbol %s not found", symbol_name);
  } else {
    LOGD("Symbol %s found at final address %p", symbol_name, (void*)sym_addr);
    void (*func)() = (void (*)())sym_addr;
    func();
    LOGD("Result of %s(): OK", symbol_name);
  }

  csoloader_unload(&lib);

  LOGD("Successfully loaded and linked %s", lib_path);

  /* TODO: Fix the bug where, in Linux, it will get permanently stuck here */

  return EXIT_SUCCESS;
}
