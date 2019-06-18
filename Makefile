

trezor-crypto-src = \
	trezor-crypto/memzero.c \
	trezor-crypto/pbkdf2.c \
	trezor-crypto/sha2.c \
	trezor-crypto/hmac.c \
	trezor-crypto/rand.c

all: trezor-crypto test

test: $(trezor-crypto) test.c slip39.c gf256.c misc.c vectors.c
	gcc -std=gnu99 -I. -I./trezor-crypto $(trezor-crypto-src) test.c slip39.c gf256.c misc.c vectors.c -o $@

.PHONY: trezor-crypto
trezor-crypto:
	git submodule update --init --recursive
