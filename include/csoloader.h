#ifndef CSOLOADER_H
#define CSOLOADER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "elf_util.h"
#include "linker.h"

struct csoloader {
  char *lib_path;
  struct csoloader_elf *img;
  struct linker linker;
};

/* INFO: Load a library to memory and link it */
bool csoloader_load(struct csoloader *lib, const char *lib_path);

/* INFO: Unload the library and free all related resources */
bool csoloader_unload(struct csoloader *lib);

/* INFO: Free resources related to the library without unloading it */
bool csoloader_abandon(struct csoloader *lib);

/* INFO: Get the address of a symbol in the loaded library */
void *csoloader_get_symbol(struct csoloader *lib, const char *symbol_name);

/* INFO: Deinitializes all internal global resources */
void csoloader_deinit(void);

#ifdef __cplusplus
}
#endif

#endif /* CSOLOADER_H */