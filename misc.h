#ifndef __MISC_H__
#define __MISC_H__

void dumphex(uint8_t *b, int l);
int fromhex(uint8_t *buf, uint32_t *buf_len, const char *str);
size_t memscpy(void *d, size_t ds, const void *s, size_t ss);

#endif
