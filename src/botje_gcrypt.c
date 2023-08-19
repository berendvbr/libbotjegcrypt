#include "botje_gcrypt.h"

void botje_gcrypt__init() {

    if(!gcry_check_version(NEED_LIBGCRYPT_VERSION)) {
        fprintf(stderr, "botje_gcrypt__init: libgcrypt is too old (need %s, have %s)\n", NEED_LIBGCRYPT_VERSION, gcry_check_version(NULL));
        exit(2);
    }

    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
}

int64_t botje_gcrypt__decrypt_string(unsigned char *str_dst, unsigned char *str_src, int64_t str_src_len, unsigned char *key, unsigned char *iv, int64_t type) {

    // str_src_len should always be a multiple of 16
    if(str_src_len % 16 != 0) {
        return -1;
    }


    gcry_cipher_hd_t handle;

    int algorithm;  // no default!
    if(type == 0) {
        algorithm = GCRY_CIPHER_AES128;
    } else if(type == 1) {
        algorithm = GCRY_CIPHER_CAMELLIA128;
    } else if(type == 2) {
        algorithm = GCRY_CIPHER_SERPENT128;
    } else if(type == 3) {
        algorithm = GCRY_CIPHER_TWOFISH128;
    } else {
        printf("botje_gcrypt__decrypt_string: please provide valid algorithm/cipher\n");
        abort();
    }

    // example code: gcry_error_t gcry_cipher_open(gcry_cipher_hd_t *hd, int algo, int mode, unsigned int flags)
    gcry_error_t err1 = gcry_cipher_open(&handle, algorithm, GCRY_CIPHER_MODE_CBC, 0);
    if(err1 != 0) {
        printf("botje_gcrypt__decrypt_string err1: |%d|\n", err1);
        abort();
    }

    // example: gcry_error_t gcry_cipher_setkey(gcry_cipher_hd_t h, const void *k, size_t l)
    gcry_error_t err2 = gcry_cipher_setkey(handle, key, 16);
    if(err2 != 0) {
        printf("botje_gcrypt__decrypt_string err2: |%d|\n", err2);
        abort();
    }

    // example: gcry_error_t gcry_cipher_setiv(gcry_cipher_hd_t h, const void *k, size_t l)
    gcry_error_t err3 = gcry_cipher_setiv(handle, iv, 16);
    if(err3 != 0) {
        printf("botje_gcrypt__decrypt_string err3: |%d|\n", err3);
        abort();
    }

    // example: gcry_error_t gcry_cipher_decrypt(gcry_cipher_hd_t h, unsigned char *out, size_t outsize, const unsigned char *in, size_t inlen)
    gcry_error_t err4 = gcry_cipher_decrypt(handle, str_dst, str_src_len, str_src, str_src_len);
    if(err4 != 0) {
        printf("botje_gcrypt__decrypt_string err4: |%d|\n", err4);
        abort();
    }

    // example: void gcry_cipher_close(gcry_cipher_hd_t h)
    gcry_cipher_close(handle);

    return str_src_len;
}

int64_t botje_gcrypt__encrypt_string(unsigned char *str_dst, unsigned char *str_src, int64_t str_src_len, unsigned char *key, unsigned char *iv, int64_t type) {

    // str_src_len should always be a multiple of 16
    if(str_src_len % 16 != 0) {
        return -1;
    }


    gcry_cipher_hd_t handle;

    int algorithm;  // no default!
    if(type == 0) {
        algorithm = GCRY_CIPHER_AES128;
    } else if(type == 1) {
        algorithm = GCRY_CIPHER_CAMELLIA128;
    } else if(type == 2) {
        algorithm = GCRY_CIPHER_SERPENT128;
    } else if(type == 3) {
        algorithm = GCRY_CIPHER_TWOFISH128;
    } else {
        printf("botje_gcrypt__encrypt_string: please provide valid algorithm/cipher\n");
        abort();
    }

    // example code: gcry_error_t gcry_cipher_open(gcry_cipher_hd_t *hd, int algo, int mode, unsigned int flags)
    gcry_error_t err1 = gcry_cipher_open(&handle, algorithm, GCRY_CIPHER_MODE_CBC, 0);
    if(err1 != 0) {
        printf("botje_gcrypt__encrypt_string err1: |%d|\n", err1);
        abort();
    }

    // example: gcry_error_t gcry_cipher_setkey(gcry_cipher_hd_t h, const void *k, size_t l)
    gcry_error_t err2 = gcry_cipher_setkey(handle, key, 16);
    if(err2 != 0) {
        printf("botje_gcrypt__encrypt_string err2: |%d|\n", err2);
        abort();
    }

    // example: gcry_error_t gcry_cipher_setiv(gcry_cipher_hd_t h, const void *k, size_t l)
    gcry_error_t err3 = gcry_cipher_setiv(handle, iv, 16);
    if(err3 != 0) {
        printf("botje_gcrypt__encrypt_string err3: |%d|\n", err3);
        abort();
    }

    // example: gcry_error_t gcry_cipher_encrypt(gcry_cipher_hd_t h, unsigned char *out, size_t outsize, const unsigned char *in, size_t inlen)
    gcry_error_t err4 = gcry_cipher_encrypt(handle, str_dst, str_src_len, str_src, str_src_len);
    if(err4 != 0) {
        printf("botje_gcrypt__encrypt_string err4: |%d|\n", err4);
        abort();
    }

    // example: void gcry_cipher_close(gcry_cipher_hd_t h)
    gcry_cipher_close(handle);

    return str_src_len;
}

int64_t botje_gcrypt__digest_sha3_256_string(unsigned char *str_dst, unsigned char *str_src, int64_t str_src_len) {
    
    gcry_md_hd_t handle;

    // example: gcry_error_t gcry_md_open(gcry_md_hd_t *hd, int algo, unsigned int flags)
    gcry_error_t err = gcry_md_open(&handle, GCRY_MD_SHA3_256, GCRY_MD_FLAG_SECURE);
    if(err != 0) {
        printf("botje_gcrypt__digest_sha3_256_string err: |%d|\n", err);
        abort();
    }

    // example: void gcry_md_write(gcry_md_hd_t h, const void *buffer, size_t length)
    gcry_md_write(handle, str_src, str_src_len);

    int64_t num_bytes = 32;
    // example: unsigned char * gcry_md_read(gcry_md_hd_t h, int algo)
    unsigned char *sha3 = gcry_md_read(handle, 0);
    for(int64_t i = 0; i < num_bytes; i++) {
        str_dst[i] = sha3[i];
    }

    // example: void gcry_md_close(gcry_md_hd_t h)
    gcry_md_close(handle);

    return num_bytes;
}

int64_t botje_gcrypt__digest_sha3_256_hex_string(unsigned char *str_dst, unsigned char *str_src, int64_t str_src_len) {

    unsigned char *sha3 = calloc(1, 1024);
    int64_t sha3_len = botje_gcrypt__digest_sha3_256_string(sha3, str_src, str_src_len);

    // convert string to hex
    int64_t sha3_hex_len = 0;
    for (int64_t i = 0; i < sha3_len; i++) {
        char tmp_chars[4] = { 0,0,0,0 };
        sprintf(tmp_chars, "%02x", sha3[i]);
        strcat((char *)str_dst, tmp_chars);
        sha3_hex_len += 2;
    }

    free(sha3);

    return sha3_hex_len;
}

int64_t botje_gcrypt__random_string(unsigned char *str_dst, int64_t num_bytes) {

    // example: void gcry_randomize(unsigned char *buffer, size_t length, enum gcry_random_level level)
    gcry_randomize(str_dst, num_bytes, GCRY_VERY_STRONG_RANDOM);

    return num_bytes;
}

int64_t botje_gcrypt__random_readable_string(unsigned char *str_dst, int64_t num_bytes) {

    // decimal 48 - 57  (0-9)
    // decimal 65 - 90  (A-Z)
    // decimal 97 - 122 (a-z)
    int64_t num_done = 0;
    int64_t num_tries = 0;
    while (num_done < num_bytes) {

        unsigned char random_char[2] = { 0,0 };

        // example: void gcry_randomize(unsigned char *buffer, size_t length, enum gcry_random_level level)
        gcry_randomize(random_char, 1, GCRY_VERY_STRONG_RANDOM);

        unsigned char tmp_char = random_char[0] % 128;
        if((tmp_char >= 48 && tmp_char <= 57) || (tmp_char >= 65 && tmp_char <= 90) || (tmp_char >= 97 && tmp_char <= 122)) {
            str_dst[num_done++] = tmp_char;
        }

        if(++num_tries > num_bytes * 50)  return -1;
    }

    return num_done;
}
