/* Copyright (c) 2025 ThePedroo. All rights reserved.
 *
 * This source code is licensed under the GNU AGPLv3 License found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef LOGGING_H
#define LOGGING_H

#include <stdio.h>

#define LOGI(fmt, ...) fprintf(stdout, "INFO: " fmt "\n", ##__VA_ARGS__)
#define LOGD(fmt, ...) fprintf(stdout, "DEBUG: " fmt "\n", ##__VA_ARGS__)
#define LOGW(fmt, ...) fprintf(stderr, "WARNING: " fmt "\n", ##__VA_ARGS__)
#define LOGE(fmt, ...) fprintf(stderr, "ERROR: " fmt "\n", ##__VA_ARGS__)

#define LOGF(fmt, ...) do {                             \
    fprintf(stderr, "FATAL: " fmt "\n", ##__VA_ARGS__); \
    exit(EXIT_FAILURE);                                 \
} while (0)

#define PLOGE(fmt, ...) fprintf(stderr, "ERROR: " fmt ": %s\n", ##__VA_ARGS__, strerror(errno))

#endif /* LOGGING_H */