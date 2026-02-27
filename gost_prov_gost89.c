#include "gost_prov_lcl.h"

static int prov_gost89_set_asn1_params(void *cipher_data, ASN1_TYPE *params)
{
    GOST_Prov_Cipher_CTX *c = cipher_data;
    if (!c || !params) return 0;

    GOST_CIPHER_PARAMS *gcp = NULL;
    ASN1_OCTET_STRING *os_seq = NULL, *os_iv = NULL;
    unsigned char *der = NULL;
    int derlen = -1;
    int ret = 0;

    gcp = GOST_CIPHER_PARAMS_new();
    if (!gcp) {
        GOSTerr(GOST_F_GOST89_SET_ASN1_PARAMETERS, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    os_iv = ASN1_OCTET_STRING_new();
    if (!os_iv || !ASN1_OCTET_STRING_set(os_iv, c->iv, sizeof(c->iv))) {
        GOSTerr(GOST_F_GOST89_SET_ASN1_PARAMETERS, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    gcp->iv = os_iv;

    ASN1_OBJECT *obj = OBJ_nid2obj(c->paramNID);
    if (!obj) {
        GOSTerr(GOST_F_GOST89_SET_ASN1_PARAMETERS, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    gcp->enc_param_set = obj;

    derlen = i2d_GOST_CIPHER_PARAMS(gcp, NULL);
    if (derlen <= 0) {
        GOSTerr(GOST_F_GOST89_SET_ASN1_PARAMETERS, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    der = OPENSSL_malloc(derlen);
    if (!der) {
        GOSTerr(GOST_F_GOST89_SET_ASN1_PARAMETERS, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    unsigned char *p = der;
    i2d_GOST_CIPHER_PARAMS(gcp, &p);

    os_seq = ASN1_OCTET_STRING_new();
    if (!os_seq || !ASN1_OCTET_STRING_set(os_seq, der, derlen)) {
        GOSTerr(GOST_F_GOST89_SET_ASN1_PARAMETERS, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    ASN1_TYPE_set(params, V_ASN1_SEQUENCE, os_seq);

    ret = 1;

 err:
    OPENSSL_free(der);
    GOST_CIPHER_PARAMS_free(gcp);
    return ret;
}


int gost89_get_asn1_parameters(void *cipher_data, ASN1_TYPE *params)
{
    return -1;
}

int gost89_cipher_init_cfb(void *cipher_data,
                     const unsigned char *key,
                     const unsigned char *iv,
                     int enc)
{
    GOST_Prov_Cipher_CTX *ctx = cipher_data;
    if (!ctx || !key) return 0;

    gost_init(&ctx->cctx, &Gost28147_CryptoProParamSetA);
    gost_key(&ctx->cctx, key);

    memset(ctx->iv, 0, sizeof(ctx->iv));
    if (iv)
        memcpy(ctx->iv, iv, 8);

    ctx->count = 0;
    ctx->encrypting = enc;
    return 1;
}

int gost89_cipher_do_cfb(void *cipher_data,
                   unsigned char *out,
                   const unsigned char *in,
                   size_t inl)
{
    GOST_Prov_Cipher_CTX *ctx = cipher_data;
    if (!ctx || !in || !out) return 0;

    const unsigned char *in_ptr = in;
    unsigned char *out_ptr = out;
    size_t i = 0, j;

    unsigned char *buf = gost_prov_get_buf(ctx);
    unsigned char *iv   = gost_prov_get_iv(ctx);
    size_t count        = gost_prov_get_count(ctx);
    int encrypting      = gost_prov_is_encrypting(ctx);

    if (count > 0) {
        for (j = count, i = 0; j < 8 && i < inl; ++j, ++i, ++in_ptr, ++out_ptr) {
            unsigned char pt = *in_ptr;
            *out_ptr = buf[j] ^ pt;

            if (encrypting)
                buf[j + 8] = pt;
            else
                buf[j + 8] = *out_ptr;
        }

        if (j == 8) {
            memcpy(iv, iv + 8, 8);
            gost_prov_set_count(ctx, 0);
        } else {
            gost_prov_set_count(ctx, j);
            return 1;
        }
    }

    for (; (inl - i) >= 8; i += 8, in_ptr += 8, out_ptr += 8) {
        gostcrypt(&ctx->cctx, iv, buf);

        for (j = 0; j < 8; ++j)
            out_ptr[j] = buf[j] ^ in_ptr[j];

        if (encrypting)
            memcpy(iv, out_ptr, 8);
        else
            memcpy(iv, in_ptr, 8);
    }

    if (i < inl) {
        gostcrypt(&ctx->cctx, iv, buf);

        for (j = 0; i < inl; ++j, ++i)
            out_ptr[j] = buf[j] ^ in_ptr[j];

        gost_prov_set_count(ctx, j);
    } else {
        gost_prov_set_count(ctx, 0);
    }

    return 1;
}
