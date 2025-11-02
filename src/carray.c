/* Copyright (c) 2025 ThePedroo. All rights reserved.
 *
 * This source code is licensed under the GNU AGPLv3 License found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "logging.h"

struct carray {
  char **array;
  size_t size;
  size_t length;
};

struct carray *carray_create(size_t size) {
  struct carray *carr = (struct carray *)malloc(sizeof(struct carray));
  if (!carr) {
    LOGE("Failed to allocate memory for carray");

    return NULL;
  }

  carr->array = (char **)calloc(size, sizeof(char *));
  if (!carr->array) {
    LOGE("Failed to allocate memory for carray array");

    free(carr);

    return NULL;
  }

  carr->size = size;
  carr->length = 0;

  return carr;
}

size_t carray_length(struct carray *carr) {
  if (!carr) {
    LOGE("Invalid carray");

    return 0;
  }

  return carr->length;
}

bool carray_exists(struct carray *carr, const char *str) {
  if (!carr || !str) {
    LOGE("Invalid carray or string to check");

    return false;
  }

  for (size_t i = 0; i < carr->size; i++) {
    if (carr->array[i] && strcmp(carr->array[i], str) == 0) return true;
  }

  return false;
}

char *carray_get(struct carray *carr, size_t index) {
  if (!carr || index >= carr->size) {
    LOGE("Invalid carray or index out of bounds");

    return NULL;
  }

  return carr->array[index];
}

bool carray_add(struct carray *carr, const char *str) {
  if (!carr || !str) {
    LOGE("Invalid carray or string to add");

    return false;
  }

  for (size_t i = 0; i < carr->size; i++) {
    if (!carr->array[i]) {
      carr->array[i] = strdup(str);
      if (!carr->array[i]) {
        LOGE("Failed to duplicate string: %s", str);

        return false;
      }

      carr->length++;

      return true;
    }
  }

  LOGW("Carray is full, cannot add string: %s", str);

  return false;
}

bool carray_remove(struct carray *carr, const char *str) {
  if (!carr || !str) {
    LOGE("Invalid carray or string to remove");

    return false;
  }

  for (size_t i = 0; i < carr->size; i++) {
    if (carr->array[i] && strcmp(carr->array[i], str) == 0) {
      free(carr->array[i]);
      carr->array[i] = NULL;

      carr->length--;

      return true;
    }
  }

  LOGW("String not found in carray: %s", str);

  return false;
}

bool carray_destroy(struct carray *carr) {
  if (!carr) {
    LOGE("Invalid carray to destroy");

    return false;
  }

  for (size_t i = 0; i < carr->size; i++) {
    free(carr->array[i]);
  }

  free(carr->array);
  free(carr);

  return true;
}
