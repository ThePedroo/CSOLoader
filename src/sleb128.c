/* Copyright (c) 2025 ThePedroo. All rights reserved.
 *
 * This source code is licensed under the GNU AGPLv3 License found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <stdlib.h>
#include <stdint.h>
#include <limits.h>

#include "logging.h"

#include "sleb128.h"

void sleb128_decoder_init(sleb128_decoder *decoder, const uint8_t *buffer, size_t count) {
  decoder->current = buffer;
  decoder->end = buffer + count;
}

int64_t sleb128_decode(sleb128_decoder *decoder) {
  int64_t value = 0;
  size_t shift = 0;
  uint8_t byte;
  const size_t size = sizeof(int64_t) * CHAR_BIT;

  do {
    if (decoder->current >= decoder->end)
      LOGF("sleb128 decode failed: out of bounds");

    byte = *decoder->current++;
    value |= ((int64_t)(byte & 0x7F)) << shift;
    shift += 7;
  } while (byte & 0x80);

  if (shift < size && (byte & 0x40)) {
    value |= -((int64_t)1 << shift);
  }

  return value;
}