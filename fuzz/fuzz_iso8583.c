/* libFuzzer target: the ISO 8583 decoder must never read out of bounds, and
 * anything it accepts must re-encode to the identical bytes. */
#include "iso8583.h"

#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    iso_msg m;
    int bad;
    static uint8_t out[ISO_MAX_MSG * 2];
    size_t n = 0;
    if (iso_decode(data, size, &m, &bad) != ISO_OK) return 0;
    if (iso_encode(&m, out, sizeof out, &n) != ISO_OK) abort();
    if (n != size || memcmp(out, data, size) != 0) abort();
    return 0;
}
