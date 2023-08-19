#ifndef TESTS_BOTJE_GCRYPT_H
#define TESTS_BOTJE_GCRYPT_H

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <cmocka.h>

#include "../src/botje_gcrypt.h"

void tests_botje_gcrypt__decrypt_string_test(void **);
void tests_botje_gcrypt__encrypt_string_test(void **);

void tests_botje_gcrypt__digest_sha3_256_string(void **);
void tests_botje_gcrypt__digest_sha3_256_hex_string(void **);
void tests_botje_gcrypt__random_string_test(void **);
void tests_botje_gcrypt__random_readable_string_test(void **);

#endif
