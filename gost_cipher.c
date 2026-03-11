// gost_cipher.c

#include "gost_cipher.h"
#include <string.h>

GOST_CIPHER_CTX* gost_cipher_ctx_new(void) {
    GOST_CIPHER_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (!ctx)
        return NULL;

    ctx->cipher_desc = NULL;
    ctx->algctx_size = 0;
    ctx->algctx = NULL;
    return ctx;
}

void gost_cipher_ctx_free(GOST_CIPHER_CTX *ctx) {
    if (!ctx)
        return;

    if (ctx->algctx && ctx->cipher_desc &&
        GET_MEMBER(GOST_cipher, ctx->cipher_desc, cleanup)) {
        GET_MEMBER(GOST_cipher, ctx->cipher_desc, cleanup)(ctx);
    }

    OPENSSL_clear_free(ctx->algctx, ctx->algctx_size);
    OPENSSL_free(ctx);
}

int gost_cipher_ctx_copy(GOST_CIPHER_CTX *out, const GOST_CIPHER_CTX *in) {
    if (!out || !in)
        return 0;

    memcpy(out, in, sizeof(*out));

    if (out->algctx_size > 0) {
        out->algctx = OPENSSL_malloc(out->algctx_size);
        if (!out->algctx)
            return 0;
        memcpy(out->algctx, in->algctx, out->algctx_size);
    } else {
        out->algctx = NULL;
    }

    return 1;
}


const char* gost_cipher_get0_name(const GOST_cipher *desc) {
    if (!desc)
        return NULL;

    int nid = GET_MEMBER(GOST_cipher, desc, nid);
    return OBJ_nid2sn(nid);
}

int gost_cipher_get_iv_len(const GOST_CIPHER_CTX *ctx) {
    if (!ctx || !ctx->cipher_desc)
        return 0;

    return GET_MEMBER(GOST_cipher, ctx->cipher_desc, iv_len);
}
