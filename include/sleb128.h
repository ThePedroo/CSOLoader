/* Copyright (c) 2025 ThePedroo. All rights reserved.
 *
 * This source code is licensed under the GNU AGPLv3 License found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef SLEB128_H
#define SLEB128_H

typedef struct {
  const uint8_t *current;
  const uint8_t *end;
} sleb128_decoder;

void sleb128_decoder_init(sleb128_decoder *decoder, const uint8_t *buffer, size_t count);

int64_t sleb128_decode(sleb128_decoder *decoder);

#endif /* SLEB128_H */