#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "pbkdf2.h"
#include "memzero.h"
#include "hmac.h"
#include "rand.h"

#include "slip39_wordlist.h"
#include "slip39.h"

#include "gf256.h"

void dumphex(uint8_t *b, int l);
int fromhex(uint8_t *buf, uint32_t *buf_len, const char *str);


bool shamir_interpolate(uint8_t *result, uint8_t result_index,
                        const uint8_t *share_indices,
                        const uint8_t **share_values, uint8_t share_count,
                        size_t len);


size_t memscpy(void *d, size_t ds, const void *s, size_t ss)
{
    size_t cs;

    cs = (ds < ss) ? ds : ss;
    memcpy(d, s, cs);

    return cs;
}


// -----------------------------------------------------------------------------------------------------------------


typedef struct _RS1024_CTX {
    uint32_t c;
} RS1024_CTX;

static void _rs1024_polymod_init(RS1024_CTX* c)
{
    c->c = 1;
}

static void _rs1024_polymod_update(RS1024_CTX* c, uint32_t *val, int val_len)
{
    uint32_t b, v;
    int i, j;
    static uint32_t GEN[] = {
        0x00E0E040,
        0x01C1C080,
        0x03838100,
        0x07070200,
        0x0E0E0009,
        0x1C0C2412,
        0x38086C24,
        0x3090FC48,
        0x21B1F890,
        0x03F3F120,
    };

    for (j = 0; j < val_len; j++)
    {
        v = *val++;
        b = c->c >> 20;
        c->c = (c->c & 0xFFFFF) << 10 ^ v;
        for (i = 0; i < 10; i++)
            if ((b >> i) & 1)
                c->c ^= GEN[i];
            else
                c->c ^= 0;
    }
}

static void _rs1024_polymod_final(RS1024_CTX* c, uint32_t *chk)
{
    *chk = c->c;
}

static int rs1024_create_checksum(uint32_t *val, int val_len, uint32_t *sum)
{
    int i;
    RS1024_CTX ctx;
    uint32_t cs[8];

    _rs1024_polymod_init(&ctx);
    for (i = 0; i < strlen(CUSTOMIZATION_STRING); i++)
        cs[i] = CUSTOMIZATION_STRING[i];

    _rs1024_polymod_update(&ctx, cs, strlen(CUSTOMIZATION_STRING));
    _rs1024_polymod_update(&ctx, val, val_len);
    for (i = 0; i < CHECKSUM_LENGTH_WORDS; i++)
        cs[i] = 0;

    _rs1024_polymod_update(&ctx, cs, CHECKSUM_LENGTH_WORDS);
    _rs1024_polymod_final(&ctx, sum);
    *sum ^= 1;

    return 0;
}

static int rs1024_verify_checksum(uint32_t *val, int val_len)
{
    int i;
    RS1024_CTX ctx;
    uint32_t cs[8], sum;

    _rs1024_polymod_init(&ctx);
    for (i = 0; i < strlen(CUSTOMIZATION_STRING); i++)
        cs[i] = CUSTOMIZATION_STRING[i];

    _rs1024_polymod_update(&ctx, cs, strlen(CUSTOMIZATION_STRING));
    _rs1024_polymod_update(&ctx, val, val_len);
    _rs1024_polymod_final(&ctx, &sum);

    return (sum == 1)? 0: -1;
}

/*
    id: identifier
    ie: iteration_exponent
    gi: group_index
    gt: group_threshold
    gc: group_count
    mi: member_index
    mt: member_threshold
    v: value
    vl: value len

    o: output
    ol: output len
*/
int encode_mnemonic(uint16_t id, uint16_t ie, uint16_t gi, uint16_t gt, uint16_t gc,
                uint16_t mi, uint16_t mt, uint8_t *v, int vl, char *o, uint32_t ol)
{
    int i, ms = 33; // max words
    uint32_t words[ms];
    int vc, bits, w;
    uint32_t p;

    if ((vl == 0) || (vl > 32))
        return -1;

    memzero(words, sizeof(words));
    w = 0;
    words[w++] = id >> 5 & 0xFFFFF;                                                   // id(10)
    words[w++] = ((id & 0x1F) << 5) | (ie & 0x1F);                                    // id(5) + ie (5)
    words[w++] = ((gi & 0xF) << 6) | (((gt-1) & 0xF) << 2) | (((gc-1) >> 2) & 0x3);   // gi(4) + gt(4) + gc(2)
    words[w++] = (((gc-1) & 0x3) << 8) | (mi & 0xF) << 4 | ((mt-1) & 0xF);            // gc(2) + mi(4) + mt(4)

    vc = (vl * 8) / 10;
    if ((vl * 8) % 10)
    {
        vc++;
        bits = 10 - ((vl * 8) % 10);
    }
    else
    {
        bits = 0;
    }

    p = 0;
    for (i = 0; i < vl; i++)
    {
        p = p << 8 | *v++;
        bits += 8;

        while(bits >= 10)
        {
            words[w++] = (p >> (bits - 10)) & 0x3FF;
            bits -= 10;
            p = p & ((0x1UL << bits) - 1);
        }
    }

    if (rs1024_create_checksum(words, w, &p) != 0)
        return -2;

    words[w++] = (p >> 20) & 0x3FF;
    words[w++] = (p >> 10) & 0x3FF;
    words[w++] = p & 0x3FF;

    // check output length
    p = 0;
    for (i = 0; i < w; i++)
        p += strlen(slip39_wordlist[words[i]]) + 1;

    if (p > ol)
        return -3;

    *o = 0;
    for (i = 0; i < w; i++)
    {
        char *s;

        s = (char *)slip39_wordlist[words[i]];
        p = strlen(s);
        memcpy(o, s, p);
        o += p;

        if (i != (w - 1))
            *o++ = ' ';
        else
            *o = 0;
    }

    return 0;
}

/*
    SplitSecret(T, N, S)
    Input: threshold T, number of shares N, secret S
    Output: shares y1, ... , yN for share indices 0, ... , N ? 1

    t: threshold
    n: number of shares
    s: secret
    sl: secret len
    gs: group shares
    gsi: group share indices

*/
static int _split_secret(uint8_t t, uint8_t n, uint8_t *s, int sl, uint8_t **gs)
{
    uint8_t random_share_count;
    uint8_t *base_share[t];
    uint8_t pool[sl*t];
    uint8_t bi[t];
    uint8_t hash[SHA256_DIGEST_LENGTH];
    int i;

    if (t < 1)
        return -1;
    if (t > n)
        return -2;
    if (n > MAX_SHARE_COUNT)
        return -3;
    if (sl == 0)
        return -4;

    if (t == 1)
    {
        memscpy(gs[0], sl, s, sl);
        return 0;
    }

    for (i = 0; i < t; i++)
        base_share[i] = (uint8_t *)(pool + (i * sl));

    random_share_count = t - 2;
    for (i = 0; i < random_share_count; i++)
    {
        bi[i] = i;
        random_buffer(base_share[i], sl);
    }

    // SECRET_INDEX
    memcpy(base_share[t-1], s, sl);
    bi[t-1] = SECRET_INDEX;

    // DIGEST_INDEX
    random_buffer(&base_share[t-2][DIGEST_LENGTH_BYTES], sl - DIGEST_LENGTH_BYTES);
    hmac_sha256(&base_share[t-2][DIGEST_LENGTH_BYTES], sl - DIGEST_LENGTH_BYTES, s, sl, hash);
    memcpy(base_share[t-2], hash, DIGEST_LENGTH_BYTES);
    bi[t-2] = DIGEST_INDEX;

    for (i = 0; i < n; i++)
        if (!shamir_interpolate(gs[i], i, bi, (const uint8_t **)base_share, t, sl))
        {
            printf("shamir_interpolate error\n");
            return -5;
        }

    return 0;
}

/*
    t: threshold
    sl: secret len
    gs: group shares
    gsi: group share indices
*/
int _recover_secret(uint8_t t, int sl, uint8_t *gsi, const uint8_t **gs, uint8_t *result)
{
    int i, j;
    uint8_t shared_secret[sl];
    uint8_t digest_share[sl];
    uint8_t hash[SHA256_DIGEST_LENGTH];

    if (t == 1)
    {
        memcpy(result, gs[0], sl);
        return 0;
    }

    if (!shamir_interpolate(shared_secret, SECRET_INDEX, gsi, gs, t, sl))
        return -1;
    if (!shamir_interpolate(digest_share, DIGEST_INDEX, gsi, gs, t, sl))
        return -2;

    /* check digest_share hash */
    hmac_sha256(&digest_share[DIGEST_LENGTH_BYTES], sl - DIGEST_LENGTH_BYTES, shared_secret, sl, hash);
    if(memcmp(digest_share, hash, DIGEST_LENGTH_BYTES) != 0)
    {
        printf("digest error\n");
        return -3;
    }

    memcpy(result, shared_secret, sl);

    memzero(shared_secret, sl);
    memzero(digest_share, sl);

    return 0;
}


/*
    Encryption of the master secret

    L = MS[:len(S)/2]
    R = MS[len(S)/2:]
    for i in [0,1,2,3]:
        (L, R) = (R, L xor F(i, R))
    EMS = R || L

    F(i, R) = PBKDF2(PRF = HMAC-SHA256,
        Password = (i || passphrase),
        Salt = ("shamir" || id || R),
        iterations = 2500 << e,
        dkLen = n/2 bytes)

    ms: master secret
    msl: master secret len
    ems: encrypt master secret
    emsl: encrypt master secret len
    pp: passphrase
    ppl: passphrase len
    ie: iteration exponent
    id: identifier
*/
static int _encrypt(uint8_t *ms, int msl, uint8_t *ems, int emsl,
        uint8_t *pp, int ppl, uint8_t ie, uint16_t id)
{
    int j, hl = msl / 2;
    uint8_t l[hl], r[hl];
    uint8_t _r[hl], f[hl];
    int csl = strlen(CUSTOMIZATION_STRING);
    uint8_t salt[hl+csl+2];
    uint8_t pass[ppl+1];
    uint8_t i;
    uint32_t it;

    if (emsl != msl)
        return -1;
    if (msl & 1)
        return -2;

    memscpy(l, sizeof(l), ms, hl);
    memscpy(r, sizeof(r), ms + hl, hl);

    // salt
    memscpy(salt, sizeof(salt), CUSTOMIZATION_STRING, csl);
    salt[csl] = id >> 8;
    salt[csl+1] = id & 0xff;

    // pass
    memscpy(pass+1, sizeof(pass)-1 , pp, ppl);

    // iterations
    it = (BASE_ITERATION_COUNT << ie) / ROUND_COUNT;

    for (i = 0; i < ROUND_COUNT; i++)
    {
        // salt
        memscpy(salt+8, sizeof(salt)-8, r, hl);
        // pass
        pass[0] = i;

        // PBKDF2
        pbkdf2_hmac_sha256(pass, sizeof(pass), salt, sizeof(salt), it, f, sizeof(f));

        for (j = 0; j < hl; j++)
            _r[j] = l[j] ^ f[j];

        memscpy(l, sizeof(l), r, hl);
        memscpy(r, sizeof(r), _r, hl);
    }

    memscpy(ems, emsl, r, hl);
    memscpy(ems + hl, emsl - hl, l, hl);

    memzero(pass, sizeof(pass));
    memzero(salt, sizeof(salt));
    memzero(l, sizeof(l));
    memzero(r, sizeof(r));
    memzero(_r, sizeof(_r));

    return 0;
}

/*
    Decryption of the master secret

    ems: encrypt master secret
    emsl: encrypt master secret len
    ms: master secret
    msl: master secret len
    pp: passphrase
    ppl: passphrase len
    ie: iteration exponent
    id: identifier
*/
int _decrypt(uint8_t *ems, int emsl, uint8_t *ms, int msl,
        uint8_t *pp, int ppl, uint8_t ie, uint16_t id)
{
    int j, hl = emsl / 2;
    uint8_t l[hl], r[hl];
    uint8_t _r[hl], f[hl];
    int csl = strlen(CUSTOMIZATION_STRING);
    uint8_t salt[hl+csl+2];
    uint8_t pass[ppl+1];
    int i;
    uint32_t it;

    if (msl != emsl)
        return -1;
    if (emsl & 1)
        return -2;

    memscpy(l, sizeof(l), ems, hl);
    memscpy(r, sizeof(r), ems + hl, hl);

    // salt
    memscpy(salt, sizeof(salt), CUSTOMIZATION_STRING, csl);
    salt[csl] = id >> 8;
    salt[csl+1] = id & 0xff;

    // pass
    memscpy(pass+1, sizeof(pass)-1 , pp, ppl);

    // iterations
    it = (BASE_ITERATION_COUNT << ie) / ROUND_COUNT;

    for (i = ROUND_COUNT - 1; i >= 0; i--)
    {
        // salt
        memscpy(salt+8, sizeof(salt)-8, r, hl);
        // pass
        pass[0] = i;
        // PBKDF2
        pbkdf2_hmac_sha256(pass, sizeof(pass), salt, sizeof(salt), it, f, sizeof(f));

        for (j = 0; j < hl; j++)
            _r[j] = l[j] ^ f[j];

        memscpy(l, sizeof(l), r, hl);
        memscpy(r, sizeof(r), _r, hl);
    }

    memscpy(ms, msl, r, hl);
    memscpy(ms + hl, msl - hl, l, hl);

    memzero(pass, sizeof(pass));
    memzero(salt, sizeof(salt));
    memzero(l, sizeof(l));
    memzero(r, sizeof(r));
    memzero(_r, sizeof(_r));

    return 0;
}

/*
    gt: group_threshold, The number of groups required to reconstruct the master secret.
    gn: groups, A list of (member_threshold, member_count) pairs for each group, where member_count
        is the number of shares to generate for the group and member_threshold is the number of members required to
        reconstruct the group secret.
    ms: master secret
    msl: master secret len
    pp: passphrase
    ppl: passphrase len
    ie: iteration_exponent

    ml: mnemonics list array
*/
int generate_mnemonics(uint8_t gt, uint8_t gn, uint8_t *ms, int msl, uint8_t *pp, int ppl, uint8_t ie, char **ml)
{
    int i;
    uint8_t ems[msl];
    uint16_t identifier;
    uint8_t *gs[gn];
    uint8_t *gs_pool;

    if (msl == 0)
        return -1;

    // check passphrase
    for (i = 0; i < ppl; i++)
        if (!((pp[i] >= 32) && (pp[i] <= 126)))
            return -1;

    random_buffer((void *)&identifier, sizeof(identifier));

    identifier = 0x3761; // for test
    identifier &= ((1 << ID_LENGTH_BITS) - 1);

    _encrypt(ms, msl, ems, msl, pp, ppl, ie, identifier);

    printf("encrypt master secret\n");
    dumphex(ems, msl);

    gs_pool = (uint8_t *)malloc(msl * gn);
    if (gs_pool == NULL)
        return -1;

    for (i = 0; i < gn; i++)
        gs[i] = gs_pool + i * msl;

    _split_secret(gt, gn, ems, msl, gs);

    for (i = 0; i < gn; i++)
        encode_mnemonic(identifier, ie, 0, 1, 1,
                i, gt, gs[i], msl, ml[i], MNEMONIC_LIST_LEN);

    free(gs_pool);
    return 0;
}


static int mnemonic_to_indices(char *ml, uint32_t *words, int *wc)
{
    int i, j, k, c;
    char current_word[12];

    if (!ml)
        return -1;

    i = 0; c = 0;

    while (ml[i])
    {
        if (ml[i] == ' ')
            c++;
        i++;
    }
    c++;

    if (c > 33)
        return -2;

    i = 0; c = 0;
    while (ml[i])
    {
        j = 0;
        while (ml[i] != ' ' && ml[i] != 0)
        {
            if (j >= sizeof(current_word) - 1)
                return -3;
            current_word[j] = ml[i];
            i++; j++;
        }

        current_word[j] = 0;
        if (ml[i] != 0)
            i++;

        k = 0;
        for (;;)
        {
            if (!slip39_wordlist[k])    // word not found
                return -4;
            if (strcmp(current_word, slip39_wordlist[k]) == 0) // word found on index k
            {
                if (c >= *wc)
                    return -5;
                words[c++] = k;
                break;
            }
            k++;
        }
    }
    *wc = c;
    return 0;
}

int decode_mnemonic(char *ml,
                uint16_t *id, uint16_t *ie,
                uint16_t *gi, uint16_t *gt, uint16_t *gc,
                uint16_t *mi, uint16_t *mt,
                uint8_t *v, int *vl)
{
    uint32_t words[33];
    int i, j, wc, r, vc;
    int padding, msl;
    uint32_t p, bits;

    wc = 33;
    mnemonic_to_indices(ml, words, &wc);

    if (wc <= 6)
        return -1;

    r = rs1024_verify_checksum(words, wc);
    if (r != 0)
        return -2;

    padding = (wc - 7) * 10 % 8;
    msl = (wc - 7) * 10 / 8;

    if (*vl < msl)
        return -3;

    *id = words[0] << 5 | words[1] >> 5;
    *ie = words[1] & 0x1f;
    *gi = words[2] >> 6;
    *gt = ((words[2] >> 2) & 0x1f) + 1;
    *gc = ((words[2] & 0x3) << 8 | (words[3] >> 8) & 0x3) + 1;
    *mi = (words[3] >> 4) & 0xf;
    *mt = (words[3] & 0xf) + 1;

    j = 4;
    if (padding)
    {
        bits = 10 - padding;
        p = words[j++] & ((1<<(bits+1))-1);
    }
    else
    {
        p = 0;
        bits = 0;
    }

    vc = 0;
    while(j < wc - 3)
    {
        p = p << 10 | words[j++];
        bits += 10;

        while(bits >= 8)
        {
            *v++ = (p >> (bits - 8)) & 0xFF;
            vc++;

            if (vc >= *vl)
                return -4;
            bits -= 8;
            p = p & ((0x1UL << bits) - 1);
        }
    }
    *vl = msl;

    return 0;
}

