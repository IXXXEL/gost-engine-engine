// gost_cipher_base.c

#include "gost_cipher_base.h"
#include <string.h>

static void gost_cipher_static_init(const GOST_cipher* d) {
}

static void gost_cipher_static_deinit(const GOST_cipher* d) {
}

static int cipher_base_init(GOST_CIPHER_CTX *ctx,
                            const unsigned char *key, const unsigned char *iv, int enc) {
    return 1;
}

static int cipher_base_do_cipher(GOST_CIPHER_CTX *ctx,
                                 unsigned char *out, const unsigned char *in, size_t len) {
    return 0;
}

static void cipher_base_cleanup(GOST_CIPHER_CTX *ctx) {}

static int cipher_base_set_asn1_params(GOST_CIPHER_CTX *ctx, ASN1_TYPE *params) {
    return 0;
}

static int cipher_base_get_asn1_params(GOST_CIPHER_CTX *ctx, ASN1_TYPE *params) {
    return 0;
}

static int cipher_base_ctrl(GOST_CIPHER_CTX *ctx, int type, int arg, void *ptr) {
    return -1;
}

const GOST_cipher GostCipher_base = {
    INIT_MEMBER(base, NULL),

    INIT_MEMBER(nid, NID_undef),
    INIT_MEMBER(block_size, 8),
    INIT_MEMBER(key_len, 32),
    INIT_MEMBER(iv_len, 8),
    INIT_MEMBER(algctx_size, 0),
    INIT_MEMBER(flags, EVP_CIPH_CBC_MODE | EVP_CIPH_NO_PADDING),

    INIT_MEMBER(init, cipher_base_init),
    INIT_MEMBER(do_cipher, cipher_base_do_cipher),
    INIT_MEMBER(cleanup, cipher_base_cleanup),
    INIT_MEMBER(set_asn1_parameters, cipher_base_set_asn1_params),
    INIT_MEMBER(get_asn1_parameters, cipher_base_get_asn1_params),
    INIT_MEMBER(ctrl, cipher_base_ctrl),

    INIT_MEMBER(static_init, gost_cipher_static_init),
    INIT_MEMBER(static_deinit, gost_cipher_static_deinit),
};
