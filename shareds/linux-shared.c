/* Copyright (c) 2025 ThePedroo. All rights reserved.
 *
 * This source code is licensed under the GNU AGPLv3 License found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <stdio.h>
#include <elf.h>
#include <fcntl.h>

#include <libelf.h>
#include <gelf.h>
#include <unistd.h>

void shared_function() {
  printf("This is a shared function from the shared library.\n");

  if (elf_version(EV_CURRENT) == EV_NONE) {
    printf("--- ELF library initialization failed ---\n");

    return;
  }

  printf("ELF library initialized successfully.\n");

  int fd = open("/proc/self/exe", O_RDONLY);
  if (fd < 0) {
    perror("open");

    return;
  }

  Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
  if (!elf) {
    printf("-------- elf_begin() failed --------\n");

    close(fd);

    return;
  }

  GElf_Ehdr ehdr;
  if (gelf_getehdr(elf, &ehdr) != &ehdr) {
    printf("-------- gelf_getehdr() failed --------\n");
  } else {
    printf("ELF type: %u, machine: %u\n", (unsigned)ehdr.e_type, (unsigned)ehdr.e_machine);
  }

  elf_end(elf);
  close(fd);
}