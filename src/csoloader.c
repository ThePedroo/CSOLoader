/* Copyright (c) 2025 ThePedroo. All rights reserved.
 *
 * This source code is licensed under the GNU AGPLv3 License found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <elf.h>
#include <link.h>
#include <dlfcn.h>

#include "elf_util.h"
#include "linker.h"
#include "logging.h"

#include "csoloader.h"

/* TODO: Better separate the job of the linker and the loader */

/* INFO: Global variables for argument passing */
extern int g_argc;
extern char **g_argv;
extern char **g_envp;

bool csoloader_load(struct csoloader *lib, const char *lib_path) {
  struct loaded_dep dep_info = { 0 };
  void *map_start = linker_load_library_manually(lib_path, &dep_info);
  if (!map_start) {
    LOGE("Failed to load library: %s", lib_path);

    return false;
  }

  struct csoloader_elf *elf_image = csoloader_elf_create(lib_path, map_start);
  if (!elf_image) {
    LOGE("Failed to create ELF image for %s", lib_path);

    if (dep_info.map_size > 0)
      munmap(map_start, dep_info.map_size);

    return false;
  }

  if (!linker_init(&lib->linker, elf_image)) {
    LOGE("Failed to initialize linker for %s", lib_path);

    csoloader_elf_destroy(elf_image);
    if (dep_info.map_size > 0)
      munmap(map_start, dep_info.map_size);

    return false;
  }

  lib->linker.main_map_size = dep_info.map_size;

  if (!linker_link(&lib->linker)) {
    LOGE("Linker failed to link %s", lib_path);

    linker_destroy(&lib->linker);

    return false;
  }

  lib->img = elf_image;
  lib->lib_path = strdup(lib_path);
  if (!lib->lib_path) {
    LOGE("Failed to duplicate library path string");

    linker_destroy(&lib->linker);

    return false;
  }

  return true;
}

bool csoloader_unload(struct csoloader *lib) {
  linker_destroy(&lib->linker);

  free(lib->lib_path);
  
  memset(lib, 0, sizeof(struct csoloader));

  return true;
}

/* INFO: Free resources related to the library without unloading it */
bool csoloader_abandon(struct csoloader *lib) {
  linker_abandon(&lib->linker);

  free(lib->lib_path);
  
  memset(lib, 0, sizeof(struct csoloader));

  return true;
}

void *csoloader_get_symbol(struct csoloader *lib, const char *symbol_name) {
  return (void *)csoloader_elf_symb_address(lib->img, symbol_name);
}

void csoloader_deinit(void) {
  linker_deinit();
}

#ifdef STANDALONE_TEST
  int main(int argc, char **argv, char **envp) {
    g_argc = argc;
    g_argv = argv;
    g_envp = envp;

    if (argc < 2) {
      printf("Usage: %s [file.so]\n", argv[0]);

      return 1;
    }

    const char *lib_path = argv[1];

    struct csoloader lib = { 0 };
    if (!csoloader_load(&lib, lib_path)) {
      printf("Failed to load library: %s\n", lib_path);

      return 1;
    }

    printf("Successfully loaded library: %s\n", lib_path);

    const char *symbol_name = "shared_function";
    void (*symbol_addr)(void) = csoloader_get_symbol(&lib, symbol_name);
    if (symbol_addr) {
      printf("Found symbol '%s' at address: %p\n", symbol_name, symbol_addr);
      
      symbol_addr();
    } else {
      printf("Symbol '%s' not found in library.\n", symbol_name);
    }
  
    if (!csoloader_unload(&lib)) {
      printf("Failed to unload library: %s\n", lib_path);

      return 1;
    }

    printf("Successfully unloaded library: %s\n", lib_path);

    return 0;
  }
#endif