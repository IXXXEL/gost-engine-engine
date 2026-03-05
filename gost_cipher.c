#include "gost_cipher.h"

 unsigned char *gost_cipher_get_iv(GOST_CIPHER_CTX *ctx)
{
    return ctx->iv;
}

unsigned char *gost_cipher_get_original_iv(GOST_CIPHER_CTX *ctx)
{
    return ctx->orig_iv;
}

 unsigned char *gost_cipher_get_buf(GOST_CIPHER_CTX *ctx)
{
    return ctx->buf + 8;
}

 int gost_cipher_is_encrypting(const GOST_CIPHER_CTX *ctx)
{
    return ctx->encrypting;
}

 void gost_cipher_set_num(GOST_CIPHER_CTX *ctx, size_t n)
{
    ctx->count = n;
}

 size_t gost_cipher_get_num(const GOST_CIPHER_CTX *ctx)
{
    return ctx->count;
}

 int gost_cipher_get_iv_len(const GOST_CIPHER_CTX *ctx)
{
    return ctx->cipher_desc->iv_len;
}

 int gost_cipher_get_key_len(const GOST_CIPHER_CTX *ctx)
{
    return ctx->cipher_desc->key_len;
}

 void *gost_cipher_get_app_data(const GOST_CIPHER_CTX *ctx)
{
    return ctx->app_data;
}

 void gost_cipher_set_app_data(GOST_CIPHER_CTX *ctx, void *data)
{
    ctx->app_data = data;
}

GOST_CIPHER_CTX *gost_cipher_ctx_new(void)
{
    GOST_CIPHER_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (!ctx)
        return NULL;
    ctx->cipher_desc = NULL;
    return ctx;
}

void gost_cipher_ctx_free(GOST_CIPHER_CTX *ctx)
{
    if (ctx == NULL)
        return;
    gost_destroy(&ctx->cctx);
    OPENSSL_free(ctx);
}

 const char *gost_cipher_get0_name(GOST_cipher *desc)
{
    return OBJ_nid2sn(desc->nid);
}

 unsigned long gost_cipher_get_flags(GOST_cipher *desc)
{
    return desc != NULL ? desc->flags : 0;
}

 int gost_cipher_get_block_size(GOST_cipher *desc)
{
    return desc != NULL ? desc->block_size : 0;
}

int gost_cipher_ctx_copy(GOST_CIPHER_CTX *out, const GOST_CIPHER_CTX *in)
{
    if (!out || !in) {
        fprintf(stderr, "gost_cipher_ctx_copy: NULL pointer\n");
        return 0;
    }
    out->cctx            = in->cctx;
    memcpy(out->iv,       in->iv,       sizeof(in->iv));
    memcpy(out->orig_iv,  in->orig_iv,  sizeof(in->orig_iv));
    memcpy(out->buf,      in->buf,      sizeof(in->buf));
    out->app_data        = in->app_data;
    out->count           = in->count;
    out->encrypting      = in->encrypting;
    out->paramNID        = in->paramNID;
    out->key_meshing     = in->key_meshing;
    out->cipher_desc     = in->cipher_desc;

    return 1;
}


void gost_cipher_ctx_reset(GOST_CIPHER_CTX *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->encrypting = -1;
}
