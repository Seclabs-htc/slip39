#ifndef __GF256_H__
#define __GF256_H__

#include <stdbool.h>

bool shamir_interpolate(uint8_t *result, uint8_t x,
                        const uint8_t *share_indices,
                        const uint8_t **share_values, uint8_t share_count,
                        size_t len);

#endif