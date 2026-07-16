/* Copyright (c) 2025 ThePedroo. All rights reserved.
 *
 * This source code is licensed under the GNU AGPLv3 License found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "carray.h"
#include "logging.h"

struct carray {
  char **array;
  size_t size;
  size_t length;
};

struct carray *carray_create(size_t size) {
  if (size == 0) size = 1;

  struct carray *carr = (struct carray *)calloc(1, sizeof(struct carray));
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

  for (size_t i = 0; i < carr->length; i++) {
    if (strcmp(carr->array[i], str) == 0) return true;
  }

  return false;
}

char *carray_get(struct carray *carr, size_t index) {
  if (!carr || index >= carr->length) {
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

  if (carr->length == carr->size) {
    size_t new_size = carr->size * 2;
    char **new_array = (char **)realloc(carr->array, new_size * sizeof(char *));
    if (!new_array) {
      LOGE("Failed to expand carray");

      return false;
    }

    carr->array = new_array;
    carr->size = new_size;
  }

  char *copy = strdup(str);
  if (!copy) {
    LOGE("Failed to duplicate string: %s", str);

    return false;
  }

  carr->array[carr->length++] = copy;

  return true;
}

void carray_remove(struct carray *carr, const char *str) {
  if (!carr || !str) {
    LOGE("Invalid carray or string to remove");

    return;
  }

  for (size_t i = 0; i < carr->length; i++) {
    if (strcmp(carr->array[i], str) != 0) continue;

    free(carr->array[i]);
    memmove(&carr->array[i], &carr->array[i + 1], (carr->length - i - 1) * sizeof(char *));
    carr->array[--carr->length] = NULL;

    return;
  }
}

void carray_destroy(struct carray *carr) {
  if (!carr) return;

  for (size_t i = 0; i < carr->length; i++) {
    free(carr->array[i]);
  }

  free(carr->array);
  free(carr);
}
