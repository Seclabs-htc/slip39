#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "rand.h"
#include "slip39.h"

void dumphex(uint8_t *b, int l);
int fromhex(uint8_t *buf, uint32_t *buf_len, const char *str);

uint8_t gsi[5];
uint8_t gs[5][32];
uint8_t r[32];
uint8_t m[32];

int test_slip39(void)
{
    uint8_t master_secret[32];
    int master_secret_len;
    uint16_t id, ie, gi, gt, gc, mi, mt;
    uint8_t ems[32];
    int emsl;
    int i, j;
    int gn = 5;
    uint8_t *gsb[5];
    char *ml[gn];

    // create

    #if 1
    master_secret_len = sizeof(master_secret);
    fromhex(master_secret, &master_secret_len, "dbc4ac53fcc6d33e38c63fde60dae89f");
    #else
    master_secret_len = 16;
    random_buffer(master_secret, master_secret_len);
    #endif

    printf("master secret\n");
    dumphex(master_secret, master_secret_len);

    for (i = 0; i < gn; i++)
        ml[i] = (char *)malloc(MNEMONIC_LIST_LEN);

    gt = 3;
    generate_mnemonics(gt, gn, master_secret, master_secret_len,
            NULL, 0, 0, ml);

    // dump mnemonic
    for (i = 0; i < gn; i++)
        printf("[%d] %s\n", i, ml[i]);

    for (i = 0; i < gn; i++)
    {
        emsl = sizeof(ems);
        decode_mnemonic(ml[i], &id, &ie, &gi, &gt, &gc, &mi, &mt, ems, &emsl);
        gsi[i] = mi;
        gsb[i] = gs[i];
        memcpy(gsb[i], ems, emsl);
    }

    _recover_secret(mt, emsl, gsi, (const uint8_t **)gsb, r);

    printf("encrypt master secret\n");
    dumphex(r, emsl);
    _decrypt(r, emsl, m, emsl, NULL, 0, 0, id);

    printf("master secret\n");
    dumphex(m, emsl);

    if (memcmp(master_secret, m, master_secret_len) == 0)
        printf("\n--- pass ---\n\n");
    else
        printf("\n--- fail ---\n\n");

    for (i = 0; i < gn; i++)
        free(ml[i]);
    return 0;
}


int main(void)
{
    test_slip39();

    return 0;
}
