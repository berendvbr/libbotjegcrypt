#include "tests_botje_gcrypt.h"

void tests_botje_gcrypt__decrypt_string_test(void **state) {

    // init and default values
    int64_t buf_size = 1024;
    int64_t num_chars;
    int64_t str_src_len;
    unsigned char *str_dst = malloc(buf_size);
    unsigned char key[] = "abcdabcdabcdabcd";
    unsigned char iv[]  = "dcbadcbadcbadcba";

    // aes 128 bit
    // 16 bytes
    {
        str_src_len = 16;
        memset(str_dst, 0, buf_size);
        unsigned char str_src[] = { 97, 219, 90, 101, 123, 198, 65, 14, 251, 218, 240, 187, 179, 109, 132, 82 };
        num_chars = botje_gcrypt__decrypt_string(str_dst, str_src, str_src_len, key, iv, 0);
        assert_int_equal(num_chars, 16);
        unsigned char str_dst_cmp[] = "AAAAAAAAAAAAAAAA";
        assert_memory_equal(str_dst, str_dst_cmp, num_chars);

        // make sure the rest of the buffer (str_dst) is still filled with 0's
        for(int64_t l = str_src_len; l < buf_size; l++) {
            assert_int_equal(str_dst[l], 0);
        }
    }

    // camellia 128 bit
    // 16 bytes
    {
        str_src_len = 16;
        memset(str_dst, 0, buf_size);
        unsigned char str_src[] = { 241, 166, 129, 60, 233, 147, 178, 123, 29, 197, 44, 4, 164, 107, 194, 5 };
        num_chars = botje_gcrypt__decrypt_string(str_dst, str_src, str_src_len, key, iv, 1);
        assert_int_equal(num_chars, 16);
        unsigned char str_dst_cmp[] = "AAAAAAAAAAAAAAAA";
        assert_memory_equal(str_dst, str_dst_cmp, num_chars);

        // make sure the rest of the buffer (str_dst) is still filled with 0's
        for(int64_t l = str_src_len; l < buf_size; l++) {
            assert_int_equal(str_dst[l], 0);
        }
    }

    // serpent 128 bit
    // 16 bytes
    {
        str_src_len = 16;
        memset(str_dst, 0, buf_size);
        unsigned char str_src[] = { 141, 198, 255, 144, 170, 21, 191, 200, 80, 227, 246, 224, 163, 133, 209, 134 };
        num_chars = botje_gcrypt__decrypt_string(str_dst, str_src, str_src_len, key, iv, 2);
        assert_int_equal(num_chars, 16);
        unsigned char str_dst_cmp[] = "AAAAAAAAAAAAAAAA";
        assert_memory_equal(str_dst, str_dst_cmp, num_chars);

        // make sure the rest of the buffer (str_dst) is still filled with 0's
        for(int64_t l = str_src_len; l < buf_size; l++) {
            assert_int_equal(str_dst[l], 0);
        }
    }

    // twofish 128 bit
    // 16 bytes
    {
        str_src_len = 16;
        memset(str_dst, 0, buf_size);
        unsigned char str_src[] = { 35, 177, 12, 166, 46, 108, 78, 100, 160, 246, 96, 209, 235, 86, 235, 221 };
        num_chars = botje_gcrypt__decrypt_string(str_dst, str_src, str_src_len, key, iv, 3);
        assert_int_equal(num_chars, 16);
        unsigned char str_dst_cmp[] = "AAAAAAAAAAAAAAAA";
        assert_memory_equal(str_dst, str_dst_cmp, num_chars);

        // make sure the rest of the buffer (str_dst) is still filled with 0's
        for(int64_t l = str_src_len; l < buf_size; l++) {
            assert_int_equal(str_dst[l], 0);
        }
    }

    // clean up
    free(str_dst);
}

void tests_botje_gcrypt__encrypt_string_test(void **state) {

    // init and default values
    int64_t buf_size = 1024;
    int64_t num_chars;
    int64_t str_src_len;
    unsigned char *str_dst = malloc(buf_size);
    unsigned char *key = (unsigned char *)"abcdabcdabcdabcd";
    unsigned char *iv  = (unsigned char *)"dcbadcbadcbadcba";

    // aes 128 bit
    // 16 bytes
    {
        str_src_len = 16;
        memset(str_dst, 0, buf_size);
        unsigned char str_src[] = "AAAAAAAAAAAAAAAA";
        num_chars = botje_gcrypt__encrypt_string(str_dst, str_src, str_src_len, key, iv, 0);
        assert_int_equal(num_chars, 16);
        unsigned char str_dst_cmp[] = { 97, 219, 90, 101, 123, 198, 65, 14, 251, 218, 240, 187, 179, 109, 132, 82 };
        assert_memory_equal(str_dst, str_dst_cmp, num_chars);

        // make sure the rest of the buffer (str_dst) is still filled with 0's
        for(int64_t l = str_src_len; l < buf_size; l++) {
            assert_int_equal(str_dst[l], 0);
        }
    }

    // aes 128 bit
    // 16*16 bytes, byte 0 & 16 & 32 etc, 1 & 17 & 33 etc for example are not the same!
    // no need to check it in a for loop
    {
        str_src_len = 16*16;
        memset(str_dst, 0, buf_size);
        unsigned char str_src[] = "AAAAAAAAAAAAAAAA";
        num_chars = botje_gcrypt__encrypt_string(str_dst, str_src, str_src_len, key, iv, 0);
        assert_int_equal(num_chars, 16*16);

        // make sure the rest of the buffer (str_dst) is still filled with 0's
        for(int64_t l = str_src_len; l < buf_size; l++) {
            assert_int_equal(str_dst[l], 0);
        }
    }
  
    // camellia 128 bit
    // 16 bytes
    {
        str_src_len = 16;
        memset(str_dst, 0, buf_size);
        unsigned char str_src[] = "AAAAAAAAAAAAAAAA";
        num_chars = botje_gcrypt__encrypt_string(str_dst, str_src, str_src_len, key, iv, 1);
        assert_int_equal(num_chars, 16);
        unsigned char str_dst_cmp[] = { 241, 166, 129, 60, 233, 147, 178, 123, 29, 197, 44, 4, 164, 107, 194, 5 };
        assert_memory_equal(str_dst, str_dst_cmp, num_chars);

        // make sure the rest of the buffer (str_dst) is still filled with 0's
        for(int64_t l = str_src_len; l < buf_size; l++) {
            assert_int_equal(str_dst[l], 0);
        }
    }

    // serpent 128 bit
    // 16 bytes
    {
        str_src_len = 16;
        memset(str_dst, 0, buf_size);
        unsigned char str_src[] = "AAAAAAAAAAAAAAAA";
        num_chars = botje_gcrypt__encrypt_string(str_dst, str_src, str_src_len, key, iv, 2);
        assert_int_equal(num_chars, 16);
        unsigned char str_dst_cmp[] = { 141, 198, 255, 144, 170, 21, 191, 200, 80, 227, 246, 224, 163, 133, 209, 134 };
        assert_memory_equal(str_dst, str_dst_cmp, num_chars);

        // make sure the rest of the buffer (str_dst) is still filled with 0's
        for(int64_t l = str_src_len; l < buf_size; l++) {
            assert_int_equal(str_dst[l], 0);
        }
    }

    // twofish 128 bit
    // 16 bytes
    {
        str_src_len = 16;
        memset(str_dst, 0, buf_size);
        unsigned char str_src[] = "AAAAAAAAAAAAAAAA";
        num_chars = botje_gcrypt__encrypt_string(str_dst, str_src, str_src_len, key, iv, 3);
        assert_int_equal(num_chars, 16);
        unsigned char str_dst_cmp[] = { 35, 177, 12, 166, 46, 108, 78, 100, 160, 246, 96, 209, 235, 86, 235, 221 };
        assert_memory_equal(str_dst, str_dst_cmp, num_chars);

        // make sure the rest of the buffer (str_dst) is still filled with 0's
        for(int64_t l = str_src_len; l < buf_size; l++) {
            assert_int_equal(str_dst[l], 0);
        }
    }

    // clean up
    free(str_dst);
}

void tests_botje_gcrypt__digest_sha3_256_string(void **state) {

    // init and default values
    int64_t buf_size = 1024;
    int64_t num_chars;
    int64_t str_src_len;
    unsigned char *str_dst = malloc(buf_size);

    // 0 bytes
    // result in hex: a7ffc6f8 bf1ed766 51c14756 a061d662 f580ff4d e43b49fa 82d80a4b 80f8434a
    {
        str_src_len = 0;
        memset(str_dst, 0, buf_size);
        unsigned char str_src[] = "";
        num_chars = botje_gcrypt__digest_sha3_256_string(str_dst, str_src, str_src_len);
        assert_int_equal(num_chars, 32);
        unsigned char str_dst_cmp[] = {
            0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
            0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
            0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
            0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a
        };
        assert_memory_equal(str_dst, str_dst_cmp, num_chars);

        // make sure the rest of the buffer (str_dst) is still filled with 0's
        for(int64_t l = 32; l < buf_size; l++) {
            assert_int_equal(str_dst[l], 0);
        }
    }

    // 16 bytes
    // result in hex: 24163aab fd8d149f 6e1ad9e7 472ff2ac e7d79295 e4baf3d9 2b7efea4 848be250
    {
        str_src_len = 16;
        memset(str_dst, 0, buf_size);
        unsigned char str_src[] = "AAAAAAAAAAAAAAAA";
        num_chars = botje_gcrypt__digest_sha3_256_string(str_dst, str_src, str_src_len);
        assert_int_equal(num_chars, 32);
        unsigned char str_dst_cmp[] = {
            0x24, 0x16, 0x3a, 0xab, 0xfd, 0x8d, 0x14, 0x9f,
            0x6e, 0x1a, 0xd9, 0xe7, 0x47, 0x2f, 0xf2, 0xac,
            0xe7, 0xd7, 0x92, 0x95, 0xe4, 0xba, 0xf3, 0xd9,
            0x2b, 0x7e, 0xfe, 0xa4, 0x84, 0x8b, 0xe2, 0x50
        };
        assert_memory_equal(str_dst, str_dst_cmp, num_chars);

        // make sure the rest of the buffer (str_dst) is still filled with 0's
        for(int64_t l = 32; l < buf_size; l++) {
            assert_int_equal(str_dst[l], 0);
        }
    }

    // clean up
    free(str_dst);
}

void tests_botje_gcrypt__digest_sha3_256_hex_string(void **state) {

    // init and default values
    int64_t buf_size = 1024;
    int64_t num_chars;
    int64_t str_src_len;
    unsigned char *str_dst = malloc(buf_size);

    // 0 bytes
    // result in hex: a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
    {
        str_src_len = 0;
        memset(str_dst, 0, buf_size);
        unsigned char str_src[] = "";
        num_chars = botje_gcrypt__digest_sha3_256_hex_string(str_dst, str_src, str_src_len);
        assert_int_equal(num_chars, 64);
        unsigned char str_dst_cmp[] = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
        assert_memory_equal(str_dst, str_dst_cmp, num_chars);

        // make sure the rest of the buffer (str_dst) is still filled with 0's
        for(int64_t l = 64; l < buf_size; l++) {
            assert_int_equal(str_dst[l], 0);
        }
    }

    // 16 bytes
    // result in hex: 24163aabfd8d149f6e1ad9e7472ff2ace7d79295e4baf3d92b7efea4848be250
    {
        str_src_len = 16;
        memset(str_dst, 0, buf_size);
        unsigned char str_src[] = "AAAAAAAAAAAAAAAA";
        num_chars = botje_gcrypt__digest_sha3_256_hex_string(str_dst, str_src, str_src_len);
        assert_int_equal(num_chars, 64);
        unsigned char str_dst_cmp[] = "24163aabfd8d149f6e1ad9e7472ff2ace7d79295e4baf3d92b7efea4848be250";
        assert_memory_equal(str_dst, str_dst_cmp, num_chars);

        // make sure the rest of the buffer (str_dst) is still filled with 0's
        for(int64_t l = 64; l < buf_size; l++) {
            assert_int_equal(str_dst[l], 0);
        }
    }

    // clean up
    free(str_dst);
}

void tests_botje_gcrypt__random_string_test(void **state) {

    // init and default values
    int64_t buf_size = 1024;
    int64_t num_chars;
    unsigned char *str_dst = malloc(buf_size);

    int64_t str_len = 512;
    for(int64_t i = 0; i < str_len; i++) {

        memset(str_dst, 0, buf_size);
        num_chars = botje_gcrypt__random_string(str_dst, i);
        assert_int_equal(num_chars, i);
        
        // make sure not all chars are 0
        // max 10% may be zero
        int64_t num_zero = 0;
        for(int64_t l = 0; l < num_chars; l++) {
            if(str_dst[l] == 0)  num_zero++;
        }
        int64_t max_zero = i / 10;
        if(max_zero <= 0) max_zero = 1;
        assert_in_range(num_zero, 0, max_zero);
        
        // make sure the rest of the buffer (str_dst) is still filled with 0's
        for(int64_t l = i; l < buf_size; l++) {
            assert_int_equal(str_dst[l], 0);
        }
    }

    // clean up
    free(str_dst);
}

void tests_botje_gcrypt__random_readable_string_test(void **state) {

    // init and default values
    int64_t buf_size = 1024;
    int64_t num_chars;
    unsigned char *str_dst = malloc(buf_size);
    
    int64_t str_len = 128;
    for(int64_t i = 0; i < str_len; i++) {

        memset(str_dst, 0, buf_size);
        num_chars = botje_gcrypt__random_readable_string(str_dst, i);
        assert_int_equal(num_chars, i);

        // make sure all chars are between decimal 48 and 122
        for(int64_t l = 0; l < num_chars; l++) {
            assert_in_range(str_dst[l], 48, 122);
        }

        // make sure the rest of the buffer (str_dst) is still filled with 0's
        for(int64_t l = i; l < buf_size; l++) {
            assert_int_equal(str_dst[l], 0);
        }
    }

    // clean up
    free(str_dst);
}
