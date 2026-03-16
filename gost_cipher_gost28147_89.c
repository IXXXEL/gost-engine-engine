#include <assert.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/asn1.h>

#include "gost_cipher_gost28147_89.h"
#include "gost_cipher_base.h"

extern void cryptopro_key_meshing(gost_ctx *ctx, unsigned char *iv);
extern int gost_cipher_get_key_len(const GOST_CIPHER_CTX *ctx);

struct gost28147_89_ctx {
    gost_ctx cctx;
    int paramNID;
    unsigned int key_meshing;
};

DECLARE_ASN1_FUNCTIONS(GOST_CIPHER_PARAMS)

static const struct gost_cipher_info gost_cipher_list[] = {
    {NID_id_Gost28147_89_CryptoPro_A_ParamSet, &Gost28147_CryptoProParamSetA, 1},
    {NID_id_Gost28147_89_CryptoPro_B_ParamSet, &Gost28147_CryptoProParamSetB, 1},
    {NID_id_Gost28147_89_CryptoPro_C_ParamSet, &Gost28147_CryptoProParamSetC, 1},
    {NID_id_Gost28147_89_CryptoPro_D_ParamSet, &Gost28147_CryptoProParamSetD, 1},
    {NID_id_tc26_gost_28147_param_Z,          &Gost28147_TC26ParamSetZ,      1},
    {NID_id_Gost28147_89_TestParamSet,        &Gost28147_TestParamSet,       1},
    {NID_undef, NULL, 0}
};

extern void gost_init(gost_ctx *ctx, const gost_subst_block *sblock);
extern void gost_key(gost_ctx *ctx, const unsigned char *key);
extern void gost_destroy(gost_ctx *ctx);

static const struct gost_cipher_info* get_encryption_params(ASN1_OBJECT *obj)
{
    int nid;
    const struct gost_cipher_info* param;
    int i;

    if (!obj) {
        const char *params = getenv("CRYPT_PARAMS");
        if (!params || !strlen(params)) {
            for (i = 0; gost_cipher_list[i].nid != NID_undef; i++) {
                if (gost_cipher_list[i].nid == NID_id_tc26_gost_28147_param_Z)
                    return &gost_cipher_list[i];
            }
            return &gost_cipher_list[0];
        }

        nid = OBJ_txt2nid(params);
        if (nid == NID_undef) {
            fprintf(stderr, "GOST: invalid CRYPT_PARAMS='%s'\n", params);
            return NULL;
        }
    } else {
        nid = OBJ_obj2nid(obj);
    }

    for (i = 0; gost_cipher_list[i].nid != NID_undef && gost_cipher_list[i].nid != nid; i++);
    
    param = &gost_cipher_list[i];
    if (!param->sblock) {
        fprintf(stderr, "GOST: invalid cipher params NID %d\n", nid);
        return NULL;
    }

    return param;
}

static int gost28147_89_set_param(struct gost28147_89_ctx *c, int nid)
{
    const struct gost_cipher_info* param = get_encryption_params(
        (nid == NID_undef ? NULL : OBJ_nid2obj(nid))
    );
    if (!param)
        return 0;

    c->paramNID = param->nid;
    c->key_meshing = param->key_meshing;
    gost_init(&c->cctx, param->sblock);
    return 1;
}

static int gost28147_89_init_param(GOST_CIPHER_CTX *ctx,
                                   const unsigned char *key,
                                   const unsigned char *iv,
                                   int enc,
                                   int paramNID)
{
    struct gost28147_89_ctx* c = (struct gost28147_89_ctx*)gost_cipher_algctx(ctx);
    if (!c) return 0;

    if (!gost28147_89_set_param(c, paramNID))
        return 0;

    gost_cipher_set_num(ctx, 0);

    if (key) {
        gost_key(&c->cctx, key);
    }

    if (iv) {
        size_t ivlen = GET_MEMBER(GOST_cipher, ctx->cipher_desc, iv_len);
        memcpy((void*)gost_cipher_get_orig_iv(ctx), iv, ivlen);
        memcpy(gost_cipher_get_iv(ctx), iv, ivlen);
    }

    ctx->encrypting = enc;
    return 1;
}

static int gost28147_89_init(GOST_CIPHER_CTX *ctx,
                             const unsigned char *key,
                             const unsigned char *iv,
                             int enc)
{
    return gost28147_89_init_param(ctx, key, iv, enc, NID_undef);
}

static void gost28147_89_crypt_mesh(GOST_CIPHER_CTX *ctx,
                                    unsigned char *iv,
                                    unsigned char *buf)
{
    struct gost28147_89_ctx* c = (struct gost28147_89_ctx*)gost_cipher_algctx(ctx);
    if (!c) return;

    assert(gost_cipher_get_num(ctx) % 8 == 0 && gost_cipher_get_num(ctx) <= 1024);
    if (c->key_meshing && gost_cipher_get_num(ctx) == 1024) {
        cryptopro_key_meshing(&c->cctx, iv);
    }
    gostcrypt(&c->cctx, iv, buf);
    gost_cipher_set_num(ctx, (gost_cipher_get_num(ctx) % 1024) + 8);
}

static int gost28147_89_do_cfb(GOST_CIPHER_CTX *ctx,
                               unsigned char *out,
                               const unsigned char *in,
                               size_t inl)
{
    struct gost28147_89_ctx* c = (struct gost28147_89_ctx*)gost_cipher_algctx(ctx);
    if (!c) return 0;

    const unsigned char* in_ptr = in;
    unsigned char* out_ptr = out;
    size_t i = 0, j = 0;
    unsigned char* buf = gost_cipher_get_buf(ctx);
    unsigned char* iv = gost_cipher_get_iv(ctx);

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
        gost28147_89_crypt_mesh(ctx, iv, buf);
        if (!gost_cipher_is_encrypting(ctx))
            memcpy(iv, in_ptr, 8);
        for (j = 0; j < 8; j++)
            out_ptr[j] = buf[j] ^ in_ptr[j];
        if (gost_cipher_is_encrypting(ctx))
            memcpy(iv, out_ptr, 8);
    }

    if (i < inl) {
        gost28147_89_crypt_mesh(ctx, iv, buf);
        if (!gost_cipher_is_encrypting(ctx))
            memcpy(buf + 8, in_ptr, inl - i);
        for (j = 0; i < inl; j++, i++)
            out_ptr[j] = buf[j] ^ in_ptr[j];
        gost_cipher_set_num(ctx, j);
        if (gost_cipher_is_encrypting(ctx))
            memcpy(buf + 8, out_ptr, j);
    } else {
        gost_cipher_set_num(ctx, 0);
    }

    return 1;
}

static int gost28147_89_set_asn1_parameters(GOST_CIPHER_CTX *ctx, ASN1_TYPE *params)
{
    struct gost28147_89_ctx* c = (struct gost28147_89_ctx*)gost_cipher_algctx(ctx);
    if (!c) return 0;

    GOST_CIPHER_PARAMS* gcp = NULL;
    ASN1_OCTET_STRING* os_iv = NULL, *os_seq = NULL;
    unsigned char* buf = NULL;
    int len;

    gcp = GOST_CIPHER_PARAMS_new();
    if (!gcp)
        return 0;

    size_t ivlen = GET_MEMBER(GOST_cipher, ctx->cipher_desc, iv_len);
    os_iv = ASN1_OCTET_STRING_new();
    if (!os_iv ||
        !ASN1_OCTET_STRING_set(os_iv, gost_cipher_get_iv(ctx), ivlen)) {
        goto err;
    }
    gcp->iv = os_iv;

    ASN1_OBJECT_free(gcp->enc_param_set);
    gcp->enc_param_set = OBJ_nid2obj(c->paramNID);

    len = i2d_GOST_CIPHER_PARAMS(gcp, NULL);
    if (len <= 0) goto err;

    buf = OPENSSL_malloc(len);
    unsigned char* p = buf;
    i2d_GOST_CIPHER_PARAMS(gcp, &p);
    GOST_CIPHER_PARAMS_free(gcp); gcp = NULL;

    os_seq = ASN1_OCTET_STRING_new();
    if (!os_seq || !ASN1_OCTET_STRING_set(os_seq, buf, len)) {
        OPENSSL_free(buf);
        goto err;
    }
    OPENSSL_free(buf);

    ASN1_TYPE_set(params, V_ASN1_SEQUENCE, os_seq);
    return 1;

err:
    GOST_CIPHER_PARAMS_free(gcp);
    ASN1_OCTET_STRING_free(os_iv);
    if (buf) OPENSSL_free(buf);
    return 0;
}

static int gost28147_89_get_asn1_parameters(GOST_CIPHER_CTX *ctx, ASN1_TYPE *params)
{
    struct gost28147_89_ctx* c = (struct gost28147_89_ctx*)gost_cipher_algctx(ctx);
    if (!c) return 0;

    GOST_CIPHER_PARAMS* gcp = NULL;
    const unsigned char* p;
    int len, nid;

    if (params->type != V_ASN1_SEQUENCE)
        return -1;

    p = params->value.sequence->data;
    gcp = d2i_GOST_CIPHER_PARAMS(NULL, &p, params->value.sequence->length);
    if (!gcp) return 0;

    size_t ivlen = GET_MEMBER(GOST_cipher, ctx->cipher_desc, iv_len);
    len = gcp->iv->length;
    if (len != (int)ivlen) {
        GOST_CIPHER_PARAMS_free(gcp);
        return -1;
    }

    memcpy((void*)gost_cipher_get_orig_iv(ctx), gcp->iv->data, len);
    memcpy(gost_cipher_get_iv(ctx),      gcp->iv->data, len);

    nid = OBJ_obj2nid(gcp->enc_param_set);
    gost28147_89_set_param(c, nid);

    GOST_CIPHER_PARAMS_free(gcp);
    return 1;
}

static int gost28147_89_ctrl(GOST_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    struct gost28147_89_ctx* c = ctx ? (struct gost28147_89_ctx*)gost_cipher_algctx(ctx) : NULL;

    switch (type) {
    case EVP_CTRL_RAND_KEY:
        if (!RAND_priv_bytes(ptr, GET_MEMBER(GOST_cipher, ctx->cipher_desc, key_len)))
            return -1;
        return 1;

    case EVP_CTRL_SET_SBOX:
        if (!c || gost_cipher_get_num(ctx) != 0)
            return -1;
        {
            int nid = OBJ_txt2nid((const char*)ptr);
            unsigned int cur_meshing = c->key_meshing;
            gost28147_89_set_param(c, nid);
            c->key_meshing = cur_meshing;
            return 1;
        }

    case EVP_CTRL_KEY_MESH:
        if (!c || gost_cipher_get_num(ctx) != 0)
            return -1;
        c->key_meshing = (unsigned int)arg;
        return 1;

    default:
        return -1;
    }
}

static void gost28147_89_cleanup(GOST_CIPHER_CTX *ctx)
{
    struct gost28147_89_ctx* c = ctx ? (struct gost28147_89_ctx*)gost_cipher_algctx(ctx) : NULL;
    if (c)
        gost_destroy(&c->cctx);
}

const GOST_cipher Gost28147_89_cipher = {
    INIT_MEMBER(base, &GostCipher_base),

    INIT_MEMBER(nid, NID_id_Gost28147_89),
    INIT_MEMBER(block_size, 8),
    INIT_MEMBER(key_len, 32),
    INIT_MEMBER(iv_len, 8),
    INIT_MEMBER(algctx_size, sizeof(struct gost28147_89_ctx)),
    INIT_MEMBER(flags, EVP_CIPH_CFB_MODE | EVP_CIPH_NO_PADDING),

    INIT_MEMBER(init, gost28147_89_init),
    INIT_MEMBER(do_cipher, gost28147_89_do_cfb),
    INIT_MEMBER(cleanup, gost28147_89_cleanup),

    INIT_MEMBER(set_asn1_parameters, gost28147_89_set_asn1_parameters),
    INIT_MEMBER(get_asn1_parameters, gost28147_89_get_asn1_parameters),
    INIT_MEMBER(ctrl, gost28147_89_ctrl),

    INIT_MEMBER(static_init, NULL),
    INIT_MEMBER(static_deinit, NULL),
};
