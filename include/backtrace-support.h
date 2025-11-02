/* Copyright (c) 2025 ThePedroo. All rights reserved.
 *
 * This source code is licensed under the GNU AGPLv3 License found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef BACKTRACE_SUPPORT_H
#define BACKTRACE_SUPPORT_H

#include "elf_util.h"
#include <stdbool.h>

int custom_dl_iterate_phdr(int (*callback)(struct dl_phdr_info *, size_t, void *), void *data);

int custom_dladdr(const void *addr, Dl_info *info);

bool register_custom_library_for_backtrace(ElfImg *img);

bool unregister_custom_library_for_backtrace(ElfImg *img);

void register_eh_frame_for_library(ElfImg *img);

void unregister_eh_frame_for_library(ElfImg *img);

#endif /* BACKTRACE_SUPPORT_H */