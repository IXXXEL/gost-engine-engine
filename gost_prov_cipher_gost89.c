#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include "gost_prov.h"
#include "gost_prov_lcl.h"
#include "gost_prov_gost89.h"

static void prov_freectx(void *vctx)
{
    GOST_Prov_Cipher_CTX *ctx = vctx;
    if (ctx) {
        gost_cipher_cleanup(ctx);
        OPENSSL_cleanse(ctx, sizeof(*ctx));
        OPENSSL_free(ctx);
    }
}

static void *prov_newctx(void *provctx, const GOST_Prov_Cipher *descriptor)
{
    GOST_Prov_Cipher_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (!ctx) return NULL;

    ctx->cipher_desc = descriptor;
    if (!ctx->cipher_desc || !ctx->cipher_desc->init) {
        prov_freectx(ctx);
        return NULL;
    }

    return ctx;
}

static void *prov_dupctx(void *vsrc)
{
    GOST_Prov_Cipher_CTX *src = vsrc;
    if (!src) return NULL;

    GOST_Prov_Cipher_CTX *dst =
        prov_newctx(NULL, src->cipher_desc);
    if (dst == NULL)
        return NULL;

    memcpy(dst, src, sizeof(*dst));
    return dst;
}

static int prov_get_params(const GOST_Prov_Cipher *c, OSSL_PARAM params[])
{
    if (!c) return 0;

    OSSL_PARAM *p;
    if ((p = OSSL_PARAM_locate(params, "blocksize")) &&
        !OSSL_PARAM_set_size_t(p, c->block_size))
        return 0;
    if ((p = OSSL_PARAM_locate(params, "keylen")) &&
        !OSSL_PARAM_set_size_t(p, c->key_len))
        return 0;
    if ((p = OSSL_PARAM_locate(params, "ivlen")) &&
        !OSSL_PARAM_set_size_t(p, c->iv_len))
        return 0;

    return 1;
}

static int prov_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    GOST_Prov_Cipher_CTX *ctx = vctx;
    if (!ctx || !ctx->cipher_desc)
        return 0;
    return prov_get_params(ctx->cipher_desc, params);
}

static int prov_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    return 1;
}

static int prov_encrypt_init(void *vctx,
                             const unsigned char *key, size_t keylen,
                             const unsigned char *iv,  size_t ivlen)
{
    GOST_Prov_Cipher_CTX *ctx = vctx;
    if (!ctx || !key ||
        keylen != (size_t)ctx->cipher_desc->key_len ||
        (iv && ivlen != (size_t)ctx->cipher_desc->iv_len))
        return 0;

    ctx->encrypting = 1;
    return ctx->cipher_desc->init(ctx, key, iv, 1);
}

static int prov_decrypt_init(void *vctx,
                             const unsigned char *key, size_t keylen,
                             const unsigned char *iv,  size_t ivlen)
{
    GOST_Prov_Cipher_CTX *ctx = vctx;
    if (!ctx || !key ||
        keylen != (size_t)ctx->cipher_desc->key_len ||
        (iv && ivlen != (size_t)ctx->cipher_desc->iv_len))
        return 0;

    ctx->encrypting = 0;
    return ctx->cipher_desc->init(ctx, key, iv, 0);
}

static int prov_update(void *vctx,
                       unsigned char *out, size_t *outl, size_t outsize,
                       const unsigned char *in, size_t inl)
{
    GOST_Prov_Cipher_CTX *ctx = vctx;
    if (!ctx || !in || !out) return 0;

    if (ctx->cipher_desc && ctx->cipher_desc->do_cipher) {
        size_t processed = inl;
        int res = ctx->cipher_desc->do_cipher(ctx, out, in, processed);
        if (res <= 0) return 0;
        if (outl) *outl = processed;
        return 1;
    }
    return 0;
}

static int prov_final(void *vctx,
                      unsigned char *out, size_t *outl, size_t outsize)
{
    if (outl) *outl = 0;
    return 1;
}

typedef void (*fptr_t)(void);

#define MAKE_FUNCTIONS(name)                                                 \
    static int name##_get_params(OSSL_PARAM params[])                        \
    {                                                                        \
        return prov_get_params(&name, params);                              \
    }                                                                        \
                                                                             \
    static void *name##_newctx(void *provctx)                               \
    {                                                                        \
        return prov_newctx(provctx, &name);                                 \
    }                                                                        \
                                                                             \
    const OSSL_DISPATCH name##_functions[] = {                       \
        {OSSL_FUNC_CIPHER_GET_PARAMS,       (fptr_t)name##_get_params},     \
        {OSSL_FUNC_CIPHER_NEWCTX,           (fptr_t)name##_newctx},         \
        {OSSL_FUNC_CIPHER_FREECTX,          (fptr_t)prov_freectx},          \
        {OSSL_FUNC_CIPHER_DUPCTX,           (fptr_t)prov_dupctx},           \
        {OSSL_FUNC_CIPHER_GET_CTX_PARAMS,   (fptr_t)prov_get_ctx_params},   \
        {OSSL_FUNC_CIPHER_SET_CTX_PARAMS,   (fptr_t)prov_set_ctx_params},   \
        {OSSL_FUNC_CIPHER_ENCRYPT_INIT,     (fptr_t)prov_encrypt_init},     \
        {OSSL_FUNC_CIPHER_DECRYPT_INIT,     (fptr_t)prov_decrypt_init},     \
        {OSSL_FUNC_CIPHER_UPDATE,           (fptr_t)prov_update},           \
        {OSSL_FUNC_CIPHER_FINAL,            (fptr_t)prov_final},            \
        {0, NULL}                                                            \
    }


extern GOST_Prov_Cipher Gost28147_89_cipher;
MAKE_FUNCTIONS(Gost28147_89_cipher);

// const OSSL_ALGORITHM GOST_prov_ciphers[] = {
//     { SN_id_Gost28147_89, NULL, Gost28147_89_cipher_functions },
//     { NULL, NULL, NULL }
// };

// void GOST_prov_deinit_ciphers(void)
// {
// }
