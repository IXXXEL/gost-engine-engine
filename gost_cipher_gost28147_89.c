#include <assert.h>
#include <openssl/rand.h>
#include "gost_cipher.h"

static int gost_cipher_do_cfb(void *ctx,
                   unsigned char *out,
                   const unsigned char *in,
                   size_t inl);
static int gost_cipher_init(void *ctx, const unsigned char *key,
                     const unsigned char *iv, int enc);
static int gost89_set_asn1_parameters(void *ctx, ASN1_TYPE *params);
static int gost89_get_asn1_parameters(void *ctx, ASN1_TYPE *params);
static int gost_cipher_ctl(void *ctx, int type, int arg, void *ptr);
static void gost_cipher_cleanup(void *ctx);


static GOST_cipher gost_template_cipher = {
    .block_size = 8,
    .key_len = 32,
    .iv_len = 8,
    .flags = EVP_CIPH_CUSTOM_IV |
        EVP_CIPH_RAND_KEY |
        EVP_CIPH_ALWAYS_CALL_INIT,
    .cleanup = gost_cipher_cleanup,
    .ctx_size = sizeof(GOST_CIPHER_CTX),
    .set_asn1_parameters = gost89_set_asn1_parameters,
    .get_asn1_parameters = gost89_get_asn1_parameters,
    .ctrl = gost_cipher_ctl,
};

GOST_cipher Gost28147_89_cipher = {
    .nid = NID_id_Gost28147_89,
    .template = &gost_template_cipher,
    .block_size = 1,
    .flags = EVP_CIPH_CFB_MODE |
        EVP_CIPH_NO_PADDING,
    .init = gost_cipher_init,
    .do_cipher = gost_cipher_do_cfb,
};

struct gost_cipher_info gost_cipher_list[] = {
    /*- NID *//*
     * Subst block
     *//*
     * Key meshing
     */
    /*
     * {NID_id_GostR3411_94_CryptoProParamSet,&GostR3411_94_CryptoProParamSet,0},
     */
    {NID_id_Gost28147_89_CryptoPro_A_ParamSet, &Gost28147_CryptoProParamSetA,
     1},
    {NID_id_Gost28147_89_CryptoPro_B_ParamSet, &Gost28147_CryptoProParamSetB,
     1},
    {NID_id_Gost28147_89_CryptoPro_C_ParamSet, &Gost28147_CryptoProParamSetC,
     1},
    {NID_id_Gost28147_89_CryptoPro_D_ParamSet, &Gost28147_CryptoProParamSetD,
     1},
    {NID_id_tc26_gost_28147_param_Z, &Gost28147_TC26ParamSetZ, 1},
    {NID_id_Gost28147_89_TestParamSet, &Gost28147_TestParamSet, 1},
    {NID_undef, NULL, 0}
};

static const struct gost_cipher_info *get_encryption_params(ASN1_OBJECT *obj)
{
    int nid;
    const struct gost_cipher_info *param;

    if (!obj) {
        for (param = gost_cipher_list; param->sblock != NULL; param++) {
            if (param->nid == NID_id_tc26_gost_28147_param_Z)
                return param;
        }
        return gost_cipher_list;
    }

    nid = OBJ_obj2nid(obj);
    for (param = gost_cipher_list; param->sblock != NULL && param->nid != nid; param++)
        ;

    if (!param->sblock) {
        fprintf(stderr, "Invalid cipher params NID %d\n", nid);
        return NULL;
    }

    return param;
}

int gost_cipher_set_param(GOST_CIPHER_CTX *ctx, int nid)
{
    const struct gost_cipher_info *param = get_encryption_params(
        (nid == NID_undef ? NULL : OBJ_nid2obj(nid))
    );
    if (!param)
        return 0;

    ctx->paramNID = param->nid;
    ctx->key_meshing = param->key_meshing;
    ctx->count = 0;
    gost_init(&ctx->cctx, param->sblock);
    return 1;
}




/* Initializes GOST_CIPHER_CTX by paramset NID */
static int gost_cipher_init_param(GOST_CIPHER_CTX *ctx,
                                  const unsigned char *key,
                                  const unsigned char *iv,
                                  int enc,
                                  int paramNID,
                                  int mode)
{
    if (gost_cipher_get_app_data(ctx) == NULL) {
        if (!gost_cipher_set_param(ctx, paramNID))
            return 0;
        gost_cipher_set_app_data(ctx, ctx);
    }

    if (key)
        gost_key(&ctx->cctx, key);

    if (iv) {
        memcpy(gost_cipher_get_original_iv(ctx), iv,
               gost_cipher_get_iv_len(ctx));
    }

    memcpy(gost_cipher_get_iv(ctx),
           gost_cipher_get_original_iv(ctx),
           gost_cipher_get_iv_len(ctx));

    return 1;
}

/* Initializes GOST_CIPHER_CTX with default values */
static int gost_cipher_init(void *ctx, const unsigned char *key,
                     const unsigned char *iv, int enc)
{
    return gost_cipher_init_param(ctx, key, iv, enc, NID_undef,
                                  EVP_CIPH_CFB_MODE);
}

static void gost_crypt_mesh(GOST_CIPHER_CTX *ctx, unsigned char *iv, unsigned char *buf)
{
    GOST_CIPHER_CTX *c = ctx;
    assert(c->count % 8 == 0 && c->count <= 1024);
    if (c->key_meshing && c->count == 1024) {
        cryptopro_key_meshing(&(c->cctx), iv);
    }
    gostcrypt(&(c->cctx), iv, buf);
    c->count = c->count % 1024 + 8;
}

/* GOST encryption in CFB mode */
static int gost_cipher_do_cfb(void *ctx,
                              unsigned char *out,
                              const unsigned char *in,
                              size_t inl)

{
    const unsigned char *in_ptr = in;
    unsigned char *out_ptr = out;
    size_t i = 0;
    size_t j = 0;
    unsigned char *buf = gost_cipher_get_buf(ctx);
    unsigned char *iv = gost_cipher_get_iv(ctx);
/* process partial block if any */
    if (gost_cipher_get_num(ctx)) {
        for (j = gost_cipher_get_num(ctx), i = 0; j < 8 && i < inl;
             j++, i++, in_ptr++, out_ptr++) {
            if (!gost_cipher_is_encrypting(ctx))
                buf[j + 8] = *in_ptr;
            *out_ptr = buf[j] ^ (*in_ptr);
            if (gost_cipher_is_encrypting(ctx))
                buf[j + 8] = *out_ptr;
        }
        if (j == 8) {
            memcpy(iv, buf + 8, 8);
            gost_cipher_set_num(ctx, 0);
        } else {
            gost_cipher_set_num(ctx, j);
            return 1;
        }
    }

    for (; (inl - i) >= 8; i += 8, in_ptr += 8, out_ptr += 8) {
        /*
         * block cipher current iv
         */
        gost_crypt_mesh(ctx, iv, buf);
        /*
         * xor next block of input text with it and output it
         */
        /*
         * output this block
         */
        if (!gost_cipher_is_encrypting(ctx))
            memcpy(iv, in_ptr, 8);
        for (j = 0; j < 8; j++) {
            out_ptr[j] = buf[j] ^ in_ptr[j];
        }
        /* Encrypt */
        /* Next iv is next block of cipher text */
        if (gost_cipher_is_encrypting(ctx))
            memcpy(iv, out_ptr, 8);
    }
/* Process rest of buffer */
    if (i < inl) {
        gost_crypt_mesh(ctx, iv, buf);
        if (!gost_cipher_is_encrypting(ctx))
            memcpy(buf + 8, in_ptr, inl - i);
        for (j = 0; i < inl; j++, i++) {
            out_ptr[j] = buf[j] ^ in_ptr[j];
        }
        gost_cipher_set_num(ctx, j);
        if (gost_cipher_is_encrypting(ctx))
            memcpy(buf + 8, out_ptr, j);
    } else {
        gost_cipher_set_num(ctx, 0);
    }
    return 1;
}

static int gost89_set_asn1_parameters(void *cipher_data, ASN1_TYPE *params)
{
    GOST_CIPHER_CTX *ctx = cipher_data;
    GOST_CIPHER_PARAMS *gcp = NULL;
    ASN1_OCTET_STRING *os = NULL;
    unsigned char *buf = NULL, *p = NULL;
    int len;

    gcp = GOST_CIPHER_PARAMS_new();
    if (!gcp) {
        GOSTerr(GOST_F_GOST89_SET_ASN1_PARAMETERS, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    if (!ASN1_OCTET_STRING_set(
            gcp->iv,
            gost_cipher_get_iv(ctx),
            gost_cipher_get_iv_len(ctx))) {
        GOST_CIPHER_PARAMS_free(gcp);
        GOSTerr(GOST_F_GOST89_SET_ASN1_PARAMETERS, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    ASN1_OBJECT_free(gcp->enc_param_set);
    gcp->enc_param_set = OBJ_nid2obj(ctx->paramNID);

    len = i2d_GOST_CIPHER_PARAMS(gcp, NULL);
    if (len <= 0) {
        GOST_CIPHER_PARAMS_free(gcp);
        return 0;
    }

    buf = OPENSSL_malloc(len);
    p = buf;
    if (!buf || i2d_GOST_CIPHER_PARAMS(gcp, &p) != len) {
        OPENSSL_free(buf);
        GOST_CIPHER_PARAMS_free(gcp);
        GOSTerr(GOST_F_GOST89_SET_ASN1_PARAMETERS, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    GOST_CIPHER_PARAMS_free(gcp);

    os = ASN1_OCTET_STRING_new();
    if (!os || !ASN1_OCTET_STRING_set(os, buf, len)) {
        OPENSSL_free(buf);
        GOSTerr(GOST_F_GOST89_SET_ASN1_PARAMETERS, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    OPENSSL_free(buf);

    ASN1_TYPE_set(params, V_ASN1_SEQUENCE, os);
    return 1;
}


/* Store parameters into ASN1 structure */
static int gost89_get_asn1_parameters(void *cipher_data, ASN1_TYPE *params)
{
    int len;
    GOST_CIPHER_CTX *ctx = cipher_data;
    GOST_CIPHER_PARAMS *gcp = NULL;
    unsigned char *p;
    int nid;

    if (ASN1_TYPE_get(params) != V_ASN1_SEQUENCE) {
        return -1;
    }

    p = params->value.sequence->data;

    gcp = d2i_GOST_CIPHER_PARAMS(NULL, (const unsigned char **)&p,
                                 params->value.sequence->length);

    len = gcp->iv->length;
    if (len != gost_cipher_get_iv_len(ctx)) {
        GOST_CIPHER_PARAMS_free(gcp);
        GOSTerr(GOST_F_GOST89_GET_ASN1_PARAMETERS, GOST_R_INVALID_IV_LENGTH);
        return -1;
    }

    nid = OBJ_obj2nid(gcp->enc_param_set);
    if (nid == NID_undef) {
        GOST_CIPHER_PARAMS_free(gcp);
        GOSTerr(GOST_F_GOST89_GET_ASN1_PARAMETERS,
                GOST_R_INVALID_CIPHER_PARAM_OID);
        return -1;
    }

    if (!gost_cipher_set_param(ctx, nid)) {
        GOST_CIPHER_PARAMS_free(gcp);
        return -1;
    }
    /*XXX missing non-const accessor */
    memcpy((unsigned char *)gost_cipher_get_original_iv(ctx), gcp->iv->data,
           gost_cipher_get_iv_len(ctx));

    GOST_CIPHER_PARAMS_free(gcp);

    return 1;
}



/* Control function for gost cipher */
static int gost_cipher_ctl(void *ctx, int type, int arg, void *ptr)
{
    switch (type) {
    case EVP_CTRL_RAND_KEY:
        {
            if (RAND_priv_bytes
                ((unsigned char *)ptr, gost_cipher_get_key_len(ctx)) <= 0) {
                GOSTerr(GOST_F_GOST_CIPHER_CTL, GOST_R_RNG_ERROR);
                return -1;
            }
            break;
        }
        //TODO
    // case EVP_CTRL_PBE_PRF_NID:
    //     if (ptr) {
    //         const char *params = get_gost_engine_param(GOST_PARAM_PBE_PARAMS);<-----------TODO
    //         int nid = NID_id_tc26_hmac_gost_3411_2012_512;

    //         if (params) {
    //             if (!strcmp("md_gost12_256", params))
    //                 nid = NID_id_tc26_hmac_gost_3411_2012_256;
    //             else if (!strcmp("md_gost12_512", params))
    //                 nid = NID_id_tc26_hmac_gost_3411_2012_512;
    //             else if (!strcmp("md_gost94", params))
    //                 nid = NID_id_HMACGostR3411_94;
    //         }
    //         *((int *)ptr) = nid;
    //         return 1;
    //     } else {
    //         return 0;
    //     }

    case EVP_CTRL_SET_SBOX:
        if (ptr) {
            GOST_CIPHER_CTX *c = ctx;
            int nid;
            int cur_meshing;
            int ret;

            if (c == NULL) {
                return -1;
            }

            if (c->count != 0) {
                return -1;
            }

            nid = OBJ_txt2nid(ptr);
            if (nid == NID_undef) {
                return 0;
            }

            cur_meshing = c->key_meshing;
            ret = gost_cipher_set_param(c, nid);
            c->key_meshing = cur_meshing;
            return ret;
        } else {
            return 0;
        }
    case EVP_CTRL_KEY_MESH:
        {
            GOST_CIPHER_CTX *c = ctx;

            if (c == NULL) {
                return -1;
            }

            if (c->count != 0) {
                return -1;
            }

            c->key_meshing = arg;
            return 1;
        }
    default:
        GOSTerr(GOST_F_GOST_CIPHER_CTL, GOST_R_UNSUPPORTED_CIPHER_CTL_COMMAND);
        return -1;
    }
    return 1;
}

/* Cleaning up of GOST_CIPHER_CTX */
static void gost_cipher_cleanup(void *ctx)
{
    GOST_CIPHER_CTX *c = ctx;
    /*TODO*/
	//EVP_MD_CTX_free(c->omac_ctx);<-------omac?
    gost_destroy(&(c->cctx));
    gost_cipher_set_app_data(ctx, NULL);
}