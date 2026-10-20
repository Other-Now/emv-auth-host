/* libFuzzer target: BER-TLV parser bounds safety, plus a structural check —
 * every value the parser returns lies inside the input. */
#include "tlv.h"

#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    tlv_item items[32];
    size_t n = 0, i;
    if (tlv_parse(data, size, items, 32, &n) != TLV_OK) return 0;
    for (i = 0; i < n; i++) {
        if (items[i].val < data || items[i].val + items[i].len > data + size) abort();
        if (tlv_find(items, n, items[i].tag) != &items[i]) abort(); /* duplicates must have been rejected */
    }
    return 0;
}
