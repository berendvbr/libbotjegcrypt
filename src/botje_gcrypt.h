#ifndef BOTJE_GCRYPT_H
#define BOTJE_GCRYPT_H

#include <gcrypt.h>
#include <stdio.h>
#include <stdlib.h>

#define NEED_LIBGCRYPT_VERSION "1.10.2"

void botje_gcrypt__init();

int64_t botje_gcrypt__decrypt_string(unsigned char *, unsigned char *, int64_t, unsigned char *, unsigned char *, int64_t);
int64_t botje_gcrypt__encrypt_string(unsigned char *, unsigned char *, int64_t, unsigned char *, unsigned char *, int64_t);

int64_t botje_gcrypt__digest_sha3_256_string(unsigned char *, unsigned char *, int64_t);
int64_t botje_gcrypt__digest_sha3_256_hex_string(unsigned char *, unsigned char *, int64_t);
int64_t botje_gcrypt__random_string(unsigned char *, int64_t);
int64_t botje_gcrypt__random_readable_string(unsigned char *, int64_t);

#endif
