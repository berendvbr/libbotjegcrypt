#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include "tests_botje_gcrypt.h"

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(tests_botje_gcrypt__decrypt_string_test),
        cmocka_unit_test(tests_botje_gcrypt__encrypt_string_test),
        cmocka_unit_test(tests_botje_gcrypt__digest_sha3_256_string),
        cmocka_unit_test(tests_botje_gcrypt__digest_sha3_256_hex_string),
        cmocka_unit_test(tests_botje_gcrypt__random_string_test),
        cmocka_unit_test(tests_botje_gcrypt__random_readable_string_test),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
