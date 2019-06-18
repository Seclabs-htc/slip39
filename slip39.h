#ifndef __SLIP_39_H__
#define __SLIP_39_H__

#define MNEMONIC_LIST_LEN (33 * 11)
#define MAX_SAHRE_VALUE_LEN 32

int generate_mnemonics(uint8_t gt, uint8_t gn, uint8_t *ms, int msl, uint8_t *pp, int ppl, uint8_t ie, char **ml);
int combine_mnemonics(int gn, char *ml[], uint8_t *pp, int ppl, uint8_t *ms, int *msl);


#endif
