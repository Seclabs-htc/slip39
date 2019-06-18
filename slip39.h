#ifndef __SLIP_39_H__
#define __SLIP_39_H__


#define ID_LENGTH_BITS 15               /* The length of the random identifier in bits */
#define CHECKSUM_LENGTH_WORDS 3         /* The length of the RS1024 checksum in words. */
#define DIGEST_LENGTH_BYTES 4           /* The length of the digest of the shared secret in bytes. */
#define SECRET_INDEX 255                /* The index of the share containing the shared secret. */
#define DIGEST_INDEX 254                /* The index of the share containing the digest of the shared secret. */
#define MAX_SHARE_COUNT 16              /* The maximum number of shares that can be created. */
#define ROUND_COUNT 4                   /* The number of rounds to use in the Feistel cipher. */
#define BASE_ITERATION_COUNT 10000      /* The minimum number of iterations to use in PBKDF2. */
#define CUSTOMIZATION_STRING "shamir"   /* The customization string used in the RS1024 checksum and in the PBKDF2 salt. */

#define MNEMONIC_LIST_LEN (33 * 11)



int generate_mnemonics(uint8_t gt, uint8_t gn, uint8_t *ms, int msl, uint8_t *pp, int ppl, uint8_t ie, char **ml);
int decode_mnemonic(char *ml, uint16_t *id, uint16_t *ie, uint16_t *gi, uint16_t *gt, uint16_t *gc, uint16_t *mi, uint16_t *mt, uint8_t *v, int *vl);

int _recover_secret(uint8_t t, int sl, uint8_t *gsi, const uint8_t **gs, uint8_t *result);
int _decrypt(uint8_t *ems, int emsl, uint8_t *ms, int msl, uint8_t *pp, int ppl, uint8_t ie, uint16_t id);


#endif
