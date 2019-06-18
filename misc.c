#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>

int fromhex(uint8_t *buf, uint32_t *buf_len, const char *str)
{
    size_t i, len = strlen(str) / 2;

    if (len > *buf_len)
        return -1;

    for (i = 0; i < len; i++) {
        uint8_t c = 0;
        if (str[i * 2] >= '0' && str[i*2] <= '9') c += (str[i * 2] - '0') << 4;
        if ((str[i * 2] & ~0x20) >= 'A' && (str[i*2] & ~0x20) <= 'F') c += (10 + (str[i * 2] & ~0x20) - 'A') << 4;
        if (str[i * 2 + 1] >= '0' && str[i * 2 + 1] <= '9') c += (str[i * 2 + 1] - '0');
        if ((str[i * 2 + 1] & ~0x20) >= 'A' && (str[i * 2 + 1] & ~0x20) <= 'F') c += (10 + (str[i * 2 + 1] & ~0x20) - 'A');
        buf[i] = c;
    }
    *buf_len = len;
    return 0;
}

static char hex_table[] = "0123456789abcdef";

void dumphex(uint8_t *b, int l)
{
    int i, c;
    char obuf[32 * 2 + 1];

    if (b == NULL)
        return;

    while (l >= 32)
    {
        memset(obuf, 0, sizeof(obuf));
        for (i = 0; i < 32; i++)
        {
            int c0, c1;

            c = *b++; l--;
            c0 = (c >> 4) & 0xf;
            c1 = c & 0x0f;
            obuf[i*2] = hex_table[c0];
            obuf[i*2+1] = hex_table[c1];
            obuf[i*2+2] = 0;
        }
        printf("%s\n", obuf);
    }
    if (l > 0)
    {
        memset(obuf, 0, sizeof(obuf));
        for (i = 0; i < l; i++)
        {
            int c0, c1;

            c = *b++;
            c0 = (c >> 4) & 0xf;
            c1 = c & 0x0f;
            obuf[i*2] = hex_table[c0];
            obuf[i*2+1] = hex_table[c1];
            obuf[i*2+2] = 0;
        }
        printf("%s\n", obuf);
    }
}

size_t memscpy(void *d, size_t ds, const void *s, size_t ss)
{
    size_t cs;

    cs = (ds < ss) ? ds : ss;
    memcpy(d, s, cs);

    return cs;
}
