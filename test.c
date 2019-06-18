#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "rand.h"
#include "slip39.h"

void dumphex(uint8_t *b, int l);
int fromhex(uint8_t *buf, uint32_t *buf_len, const char *str);
int test_vectors(void);


int simple_test(void)
{
    uint8_t master_secret[32];
    int master_secret_len;
    uint16_t gt;
    int i, j;
    int gn = 5;
    char *ml[gn];
    char *dml[5];
    uint8_t ms[32];
    int msl;

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

    printf("\n");
    for (i = 0; i < gn; i++)
        printf("%s\n", ml[i]);
    printf("\n");

    // choice 4, 3, 0 for decode
    dml[0] = ml[4];
    dml[1] = ml[3];
    dml[2] = ml[0];
    msl = sizeof(ms);
    combine_mnemonics(gt, dml, NULL, 0, ms, &msl);

    printf("master secret\n");
    dumphex(ms, msl);

    if ((msl == master_secret_len) &&
        memcmp(master_secret, ms, msl) == 0)
    {
        printf("\n--- pass ---\n\n");
    }
    else
    {
        printf("\n--- fail ---\n\n");
    }

    for (i = 0; i < gn; i++)
        free(ml[i]);
    return 0;
}


int main(void)
{
    simple_test();
    test_vectors();

    return 0;
}
