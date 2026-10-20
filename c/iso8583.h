/* ISO 8583:1987 codec for the subset of data elements this host uses.
 *
 * Wire format: 4-byte ASCII MTI, binary primary bitmap (+ binary secondary
 * bitmap when bit 1 is set), then fields in bit order. Numeric and text
 * fields are ASCII; LLVAR/LLLVAR length prefixes are ASCII digits; DE55 (ICC
 * data) is raw binary.
 *
 * Decoding never copies: iso_field.data points into the caller's buffer, so
 * the buffer must outlive the iso_msg. iso_set() likewise stores a pointer.
 */
#ifndef EAH_ISO8583_H
#define EAH_ISO8583_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ISO_MAX_FIELDS 128
#define ISO_MAX_MSG 2048

typedef enum {
    ISO_OK = 0,
    ISO_E_SHORT,             /* buffer ends inside the bitmap or a field */
    ISO_E_MTI,               /* MTI is not 4 digits */
    ISO_E_UNSUPPORTED_FIELD, /* bitmap names a field we have no spec for */
    ISO_E_LENGTH,            /* bad or over-long LL/LLL prefix */
    ISO_E_CHARSET,           /* byte not allowed for the field's type */
    ISO_E_TRAILING,          /* bytes left after the last field */
    ISO_E_NOSPACE,           /* encode: output buffer too small */
    ISO_E_SECONDARY          /* secondary bitmap present but empty */
} iso_status;

typedef struct {
    const uint8_t *data;
    uint16_t len;
    uint8_t present;
} iso_field;

typedef struct {
    char mti[5];
    iso_field f[ISO_MAX_FIELDS + 1]; /* index = field number; f[0], f[1] unused */
} iso_msg;

void iso_init(iso_msg *m, const char *mti);
int iso_has(const iso_msg *m, int n);
int iso_field_supported(int n);

/* Validates length and charset against the field spec; stores the pointer. */
iso_status iso_set(iso_msg *m, int n, const void *data, size_t len);

/* On error, *bad_field (if non-NULL) is set to the field being parsed, or 0. */
iso_status iso_decode(const uint8_t *buf, size_t len, iso_msg *out, int *bad_field);
iso_status iso_encode(const iso_msg *m, uint8_t *out, size_t cap, size_t *written);

const char *iso_strerror(iso_status s);

#ifdef __cplusplus
}
#endif
#endif
