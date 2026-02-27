#ifndef GOST_PROV_LCL_H
#define GOST_PROV_LCL_H

#include <openssl/core.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include "e_gost_err.h"
#include "gost89.h"


typedef struct {
    gost_ctx cctx;
    unsigned char iv[8];
    unsigned char buf[16];
    size_t count;
    int encrypting;
    int paramNID;  
    unsigned int key_meshing;
    const struct gost_prov_cipher_st *cipher_desc;
} GOST_Prov_Cipher_CTX;


typedef struct gost_prov_cipher_st {
    int nid;
    int block_size;
    int key_len;
    int iv_len;
    int flags;
    int ctx_size;
    int (*init)(void *cipher_data, const unsigned char *key,
            const unsigned char *iv, int enc);
    int (*do_cipher)(void *cipher_data, unsigned char *out,
                     const unsigned char *in, size_t inl);
    void (*cleanup)(void *cipher_data);
    int (*set_asn1_params)(void *cipher_data, ASN1_TYPE *params);
    int (*get_asn1_params)(void *cipher_data, ASN1_TYPE *params);
    int (*ctrl)(void *cipher_data, int type, int arg, void *ptr);

    gost_subst_block *sblock;
} GOST_Prov_Cipher;

typedef struct {
    ASN1_OCTET_STRING *iv;
    ASN1_OBJECT *enc_param_set;
} GOST_CIPHER_PARAMS;

DECLARE_ASN1_FUNCTIONS(GOST_CIPHER_PARAMS)

static inline void gost_prov_cipher_ctx_zero(GOST_Prov_Cipher_CTX *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
}

static inline unsigned char *gost_prov_get_iv(GOST_Prov_Cipher_CTX *ctx)
{
    return ctx->iv;
}

static inline unsigned char *gost_prov_get_buf(GOST_Prov_Cipher_CTX *ctx)
{
    return ctx->buf + 8;
}

static inline size_t gost_prov_get_count(const GOST_Prov_Cipher_CTX *ctx)
{
    return ctx->count;
}

static inline void gost_prov_set_count(GOST_Prov_Cipher_CTX *ctx, size_t n)
{
    ctx->count = n;
}

static inline int gost_prov_is_encrypting(const GOST_Prov_Cipher_CTX *ctx)
{
    return ctx->encrypting;
}

static inline const struct gost_prov_cipher_st *gost_prov_get_cipher_desc(
        const GOST_Prov_Cipher_CTX *ctx)
{
    return ctx->cipher_desc;
}


#endif
