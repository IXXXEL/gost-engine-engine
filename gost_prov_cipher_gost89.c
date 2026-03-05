/**********************************************************************
 *             gost_prov_crypt.c - Initialize all ciphers             *
 *                                                                    *
 *      Copyright (c) 2021 Richard Levitte <richard@levitte.org>      *
 *     This file is distributed under the same license as OpenSSL     *
 *                                                                    *
 *         OpenSSL provider interface to GOST cipher functions        *
 *                Requires OpenSSL 3.0 for compilation                *
 **********************************************************************/

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include "gost_prov.h"
#include "gost_cipher_gost28147_89.h"

/*
 * This definitions are added in the patch to OpenSSL 3.4.2 version to support
 * GOST TLS 1.3. Definitions below must be removed when the patch is added to
 * OpenSSL upstream.
 */
#ifndef OSSL_CIPHER_PARAM_TLSTREE
# if defined(_MSC_VER)
#  pragma message("Gost-engine is built against not fully supported version of OpenSSL. \
OSSL_CIPHER_PARAM_TLSTREE definition in OpenSSL is expected.")
# else
#  warning "Gost-engine is built against not fully supported version of OpenSSL. \
OSSL_CIPHER_PARAM_TLSTREE definition in OpenSSL is expected. TLSTREE is not supported by \
the provider for cipher operations."
# endif
# define OSSL_CIPHER_PARAM_TLSTREE "tlstree"
#endif

#ifndef OSSL_CIPHER_PARAM_TLSTREE_MODE
# if defined(_MSC_VER)
#  pragma message("Gost-engine is built against not fully supported version of OpenSSL. \
OSSL_CIPHER_PARAM_TLSTREE_MODE definition in OpenSSL is expected.")
# else
#  warning "Gost-engine is built against not fully supported version of OpenSSL. \
OSSL_CIPHER_PARAM_TLSTREE_MODE definition in OpenSSL is expected. TLSTREE modes are not supported by \
the provider for encryption/decryption operations. ."
# endif
# define OSSL_CIPHER_PARAM_TLSTREE_MODE "tlstree_mode"
#endif

/*
 * Forward declarations of all generic OSSL_DISPATCH functions, to make sure
 * they are correctly defined further down.  For the algorithm specific ones
 * MAKE_FUNCTIONS() does it for us.
 */
static OSSL_FUNC_cipher_dupctx_fn cipher_dupctx;
static OSSL_FUNC_cipher_freectx_fn cipher_freectx;
static OSSL_FUNC_cipher_get_ctx_params_fn cipher_get_ctx_params;
static OSSL_FUNC_cipher_set_ctx_params_fn cipher_set_ctx_params;
static OSSL_FUNC_cipher_encrypt_init_fn cipher_encrypt_init;
static OSSL_FUNC_cipher_decrypt_init_fn cipher_decrypt_init;
static OSSL_FUNC_cipher_update_fn cipher_update;
static OSSL_FUNC_cipher_final_fn cipher_final;

struct gost_prov_crypt_ctx_st {
    /* Provider context */
    PROV_CTX *provctx;
    /* OSSL_PARAM descriptors */
    const OSSL_PARAM *known_params;
    /* GOST_cipher descriptor */
    GOST_cipher *descriptor;
    GOST_CIPHER_CTX *cctx;
};
typedef struct gost_prov_crypt_ctx_st GOST_CTX;

static void cipher_freectx(void *vgctx)
{
    GOST_CTX *gctx = vgctx;

    gost_cipher_ctx_free(gctx->cctx);
    OPENSSL_free(gctx);
}

static GOST_CTX *cipher_newctx(void *provctx, GOST_cipher *descriptor,
                                const OSSL_PARAM *known_params)
{
    GOST_CTX *gctx = OPENSSL_zalloc(sizeof(*gctx));
    if (!gctx)
        return NULL;

    gctx->provctx = provctx;
    gctx->known_params = known_params;
    gctx->descriptor = descriptor;
    gctx->cctx = gost_cipher_ctx_new();

    if (gctx->cctx == NULL) {
        cipher_freectx(gctx);
        return NULL;
    }
    return gctx;
}

static void *cipher_dupctx(void *vsrc)
{
    GOST_CTX *src = vsrc;
    GOST_CTX *dst =
        cipher_newctx(src->provctx, src->descriptor, src->known_params);

    if (dst != NULL && !gost_cipher_ctx_copy(dst->cctx, src->cctx)) {
        cipher_freectx(dst);
        dst = NULL;
    }
    return dst;
}

static int cipher_get_params(GOST_cipher *desc, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, "blocksize")) != NULL &&
        !OSSL_PARAM_set_size_t(p, desc->block_size))
        return 0;
    if ((p = OSSL_PARAM_locate(params, "ivlen")) != NULL &&
        !OSSL_PARAM_set_size_t(p, desc->iv_len))
        return 0;
    if ((p = OSSL_PARAM_locate(params, "keylen")) != NULL &&
        !OSSL_PARAM_set_size_t(p, desc->key_len))
        return 0;
    if ((p = OSSL_PARAM_locate(params, "mode")) != NULL) {
        int mode = desc->flags & EVP_CIPH_MODE;
        if (!OSSL_PARAM_set_uint(p, mode))
            return 0;
    }
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD)) != NULL) {
        const char *name = gost_cipher_get0_name(desc);
        int is_aead =
            strcmp(name, "magma-mgm") == 0 ||
            strcmp(name, "kuznyechik-mgm") == 0;
        if (is_aead && !OSSL_PARAM_set_uint(p, 1))
            return 0;
    }

    return 1;
}


static int cipher_get_ctx_params(void *vgctx, OSSL_PARAM params[])
{
    GOST_CTX *gctx = vgctx;
    OSSL_PARAM *p;

    if (!cipher_get_params(gctx->descriptor, params))
        return 0;

    if ((p = OSSL_PARAM_locate(params, "alg_id_param")) != NULL) {
        GOST_CIPHER_PARAMS *gcp = NULL;
        unsigned char *der = NULL;
        int derlen = 0;

        if (!(gcp = GOST_CIPHER_PARAMS_new()))
            return 0;
        if (!ASN1_OCTET_STRING_set(gcp->iv, gctx->cctx->iv,
                                   gost_cipher_get_iv_len(gctx->cctx))) {
            GOST_CIPHER_PARAMS_free(gcp);
            return 0;
        }
        ASN1_OBJECT_free(gcp->enc_param_set);
        gcp->enc_param_set = OBJ_nid2obj(gctx->cctx->paramNID);

        derlen = i2d_GOST_CIPHER_PARAMS(gcp, &der);
        GOST_CIPHER_PARAMS_free(gcp);

        if (derlen <= 0 || !OSSL_PARAM_set_octet_string(p, der, (size_t)derlen)) {
            OPENSSL_free(der);
            return 0;
        }
        OPENSSL_free(der);
        return 1;
    }

    if ((p = OSSL_PARAM_locate(params, "updated-iv")) != NULL) {
        const unsigned char *iv = gost_cipher_get_iv(gctx->cctx);
        size_t ivlen = gost_cipher_get_iv_len(gctx->cctx);

        return OSSL_PARAM_set_octet_ptr(p, iv, ivlen)
            || OSSL_PARAM_set_octet_string(p, iv, ivlen);
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG)) != NULL) {
        void *tag = NULL;
        size_t taglen = 0;

        if (!OSSL_PARAM_get_octet_string_ptr(p, (const void**)&tag, &taglen))
            return 0;

        return 1;
    }

    return 1;
}


static int cipher_set_ctx_params(void *vgctx, const OSSL_PARAM params[])
{
    GOST_CTX *gctx = vgctx;
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params, "alg_id_param")) != NULL) {
        ASN1_TYPE *algidparam = NULL;
        const unsigned char *der = NULL;
        size_t derlen = 0;
        GOST_CIPHER_PARAMS *gcp = NULL;

        if (!OSSL_PARAM_get_octet_string_ptr(p, (const void**)&der, &derlen))
            return 0;

        if (!(algidparam = d2i_ASN1_TYPE(NULL, &der, (long)derlen)))
            return 0;

        const unsigned char *p_seq = algidparam->value.sequence->data;
        gcp = d2i_GOST_CIPHER_PARAMS(NULL, &p_seq,
                                     algidparam->value.sequence->length);
        ASN1_TYPE_free(algidparam);

        if (!gcp)
            return 0;

        size_t ivlen = gost_cipher_get_iv_len(gctx->cctx);
        if (gcp->iv->length != (int)ivlen) {
            GOST_CIPHER_PARAMS_free(gcp);
            return 0;
        }
        memcpy(gost_cipher_get_original_iv(gctx->cctx), gcp->iv->data, ivlen);
        memcpy(gost_cipher_get_iv(gctx->cctx), gcp->iv->data, ivlen);

        int nid = OBJ_obj2nid(gcp->enc_param_set);
        gost_cipher_set_param(gctx->cctx, nid);

        GOST_CIPHER_PARAMS_free(gcp);
        return 1;
    }

    if ((p = OSSL_PARAM_locate_const(params, "padding")) != NULL) {
        return 1;
    }

    if ((p = OSSL_PARAM_locate_const(params, "key-mesh")) != NULL) {
        size_t key_mesh = 0;

        if (!OSSL_PARAM_get_size_t(p, &key_mesh))
            return 0;

        gctx->cctx->key_meshing = (unsigned int)key_mesh;
        return 1;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN)) != NULL) {
        size_t ivlen = 0;

        if (!OSSL_PARAM_get_size_t(p, &ivlen))
            return 0;
        return 1;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG)) != NULL) {
        void *tag = NULL;
        size_t taglen = 0;

        if (!OSSL_PARAM_get_octet_string_ptr(p, (const void**)&tag, &taglen))
            return 0;

        return 1;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLSTREE)) != NULL ||
        (p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLSTREE_MODE)) != NULL) {
        return 1;
    }

    return 1;
}

static int cipher_encrypt_init(void *vgctx,
                               const unsigned char *key, size_t keylen,
                               const unsigned char *iv, size_t ivlen,
                               const OSSL_PARAM params[])
{
    GOST_CTX *gctx = vgctx;

    gost_cipher_ctx_reset(gctx->cctx);

    if (!cipher_set_ctx_params(vgctx, params))
        return 0;

    if (key && keylen == gctx->descriptor->key_len) {
        gost_key(&gctx->cctx->cctx, key);
    } else if (key != NULL) {
        return 0;
    }

    if (iv && ivlen > 0) {
        size_t iv_len = gost_cipher_get_iv_len(gctx->cctx);
        if (ivlen != iv_len)
            return 0;
        memcpy(gost_cipher_get_original_iv(gctx->cctx), iv, ivlen);
        memcpy(gost_cipher_get_iv(gctx->cctx), iv, ivlen);
    }

    gctx->cctx->encrypting = 1;

    return 1;
}

static int cipher_decrypt_init(void *vgctx,
                               const unsigned char *key, size_t keylen,
                               const unsigned char *iv, size_t ivlen,
                               const OSSL_PARAM params[])
{
    GOST_CTX *gctx = vgctx;

    gost_cipher_ctx_reset(gctx->cctx);
    if (!cipher_set_ctx_params(vgctx, params))
        return 0;

    if (key && keylen == gctx->descriptor->key_len) {
        gost_key(&gctx->cctx->cctx, key);
    } else if (key != NULL) {
        return 0;
    }

    if (iv && ivlen > 0) {
        size_t iv_len = gost_cipher_get_iv_len(gctx->cctx);
        if (ivlen != iv_len)
            return 0;
        memcpy(gost_cipher_get_original_iv(gctx->cctx), iv, ivlen);
        memcpy(gost_cipher_get_iv(gctx->cctx), iv, ivlen);
    }

    gctx->cctx->encrypting = 0;

    return 1;
}


static int cipher_update(void *vgctx,
                         unsigned char *out, size_t *outl, size_t outsize,
                         const unsigned char *in, size_t inl)
{
    GOST_CTX *gctx = vgctx;

    if (outl != NULL) *outl = 0;
    if (inl == 0) return 1;

    int res = gctx->descriptor->do_cipher(
        gctx->cctx,
        out, in, inl
    );

    if (res > 0 && outl != NULL)
        *outl = inl;

    return res > 0;
}

static int cipher_final(void *vgctx,
                        unsigned char *out, size_t *outl, size_t outsize)
{

    if (outl != NULL) *outl = 0;
    return 1;
}

#define NEW_GOST89_IMPL

typedef void (*fptr_t)(void);

#define MAKE_FUNCTIONS(name)                                            \
    OSSL_FUNC_cipher_get_params_fn name##_get_params;            \
    int name##_get_params(OSSL_PARAM *params)                    \
    {                                                                   \
        return cipher_get_params((GOST_cipher *)&name, params);         \
    }                                                                   \
    OSSL_FUNC_cipher_newctx_fn name##_newctx;                    \
    void *name##_newctx(void *provctx)                           \
    {                                                                   \
        return cipher_newctx(provctx, (GOST_cipher *)&name, NULL);     \
    }                                                                 \
    const OSSL_DISPATCH name##_functions[] = {                   \
        { OSSL_FUNC_CIPHER_GET_PARAMS, (fptr_t)name##_get_params },     \
        { OSSL_FUNC_CIPHER_NEWCTX, (fptr_t)name##_newctx },             \
        { OSSL_FUNC_CIPHER_DUPCTX, (fptr_t)cipher_dupctx },             \
        { OSSL_FUNC_CIPHER_FREECTX, (fptr_t)cipher_freectx },           \
        { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (fptr_t)cipher_get_ctx_params }, \
        { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (fptr_t)cipher_set_ctx_params }, \
        { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (fptr_t)cipher_encrypt_init }, \
        { OSSL_FUNC_CIPHER_DECRYPT_INIT, (fptr_t)cipher_decrypt_init }, \
        { OSSL_FUNC_CIPHER_UPDATE, (fptr_t)cipher_update },             \
        { OSSL_FUNC_CIPHER_FINAL, (fptr_t)cipher_final },               \
        { 0, NULL },                                                    \
    }

MAKE_FUNCTIONS(Gost28147_89_cipher);
