#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include "gost_cipher.h"
#include "gost_prov.h"
#include "gost_cipher_gost28147_89.h"

static OSSL_FUNC_cipher_dupctx_fn cipher_dupctx;
static OSSL_FUNC_cipher_freectx_fn cipher_freectx;
static OSSL_FUNC_cipher_get_ctx_params_fn cipher_get_ctx_params;
static OSSL_FUNC_cipher_set_ctx_params_fn cipher_set_ctx_params;
static OSSL_FUNC_cipher_encrypt_init_fn cipher_encrypt_init;
static OSSL_FUNC_cipher_decrypt_init_fn cipher_decrypt_init;
static OSSL_FUNC_cipher_update_fn cipher_update;
static OSSL_FUNC_cipher_final_fn cipher_final;

struct gost_prov_crypt_ctx_st {
    PROV_CTX *provctx;
    const GOST_cipher *descriptor;
    GOST_CIPHER_CTX *cctx;
};
typedef struct gost_prov_crypt_ctx_st GOST_CTX;

static void cipher_freectx(void *vgctx)
{
    GOST_CTX *gctx = vgctx;
    gost_cipher_ctx_free(gctx->cctx);
    OPENSSL_free(gctx);
}

static GOST_CTX *cipher_newctx(void *provctx, const GOST_cipher *descriptor)
{
    GOST_CTX *gctx = OPENSSL_zalloc(sizeof(*gctx));
    if (!gctx)
        return NULL;

    gctx->provctx = provctx;
    gctx->descriptor = descriptor;

    gctx->cctx = gost_cipher_ctx_new();
    if (gctx->cctx == NULL) {
        cipher_freectx(gctx);
        return NULL;
    }

    size_t algctx_size = GET_MEMBER(GOST_cipher, descriptor, algctx_size);
    if (algctx_size > 0) {
        gctx->cctx->algctx_size = algctx_size;
        gctx->cctx->algctx = OPENSSL_zalloc(algctx_size);
        if (!gctx->cctx->algctx) {
            cipher_freectx(gctx);
            return NULL;
        }
    }

    gost_cipher_init_fn init = GET_MEMBER(GOST_cipher, descriptor, init);
    if (init && !init(gctx->cctx, NULL, NULL, -1)) {
        fprintf(stderr, "DEBUG: init failed for %s\n", gost_cipher_get0_name(descriptor));
        cipher_freectx(gctx);
        return NULL;
    }

    return gctx;
}

static void *cipher_dupctx(void *vsrc)
{
    GOST_CTX *src = vsrc;
    GOST_CTX *dst = cipher_newctx(src->provctx, src->descriptor);

    if (dst != NULL && !gost_cipher_ctx_copy(dst->cctx, src->cctx)) {
        cipher_freectx(dst);
        dst = NULL;
    }
    return dst;
}

static int cipher_get_params(const GOST_cipher *desc, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, "blocksize")) != NULL &&
        !OSSL_PARAM_set_size_t(p, GET_MEMBER(GOST_cipher, desc, block_size)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, "ivlen")) != NULL &&
        !OSSL_PARAM_set_size_t(p, GET_MEMBER(GOST_cipher, desc, iv_len)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, "keylen")) != NULL &&
        !OSSL_PARAM_set_size_t(p, GET_MEMBER(GOST_cipher, desc, key_len)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, "mode")) != NULL) {
        int mode = GET_MEMBER(GOST_cipher, desc, flags) & EVP_CIPH_MODE;
        if (!OSSL_PARAM_set_uint(p, mode))
            return 0;
    }
    return 1;
}

static int cipher_get_ctx_params(void *vgctx, OSSL_PARAM params[])
{
    GOST_CTX *gctx = vgctx;

    if (!cipher_get_params(gctx->descriptor, params))
        return 0;

    OSSL_PARAM *p = OSSL_PARAM_locate(params, "alg_id_param");
    if (p != NULL) {
        ASN1_TYPE* algidparam = ASN1_TYPE_new();
        if (!algidparam)
            return 0;

        gost_cipher_get_asn1_params_fn get_asn1 =
            GET_MEMBER(GOST_cipher, gctx->descriptor, get_asn1_parameters);
        int res = get_asn1(gctx->cctx, algidparam);

        if (res <= 0) {
            ASN1_TYPE_free(algidparam);
            return 0;
        }

        unsigned char* der = NULL;
        int derlen = i2d_ASN1_TYPE(algidparam, &der);
        ASN1_TYPE_free(algidparam);

        if (derlen <= 0 || !OSSL_PARAM_set_octet_string(p, der, (size_t)derlen)) {
            OPENSSL_free(der);
            return 0;
        }
        OPENSSL_free(der);
        return 1;
    }

    p = OSSL_PARAM_locate(params, "updated-iv");
    if (p != NULL) {
        const unsigned char* iv = gost_cipher_get_iv(gctx->cctx);
        size_t ivlen = GET_MEMBER(GOST_cipher, gctx->descriptor, iv_len);

        return OSSL_PARAM_set_octet_ptr(p, iv, ivlen)
            || OSSL_PARAM_set_octet_string(p, iv, ivlen);
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        void* tag = NULL;
        size_t taglen = 0;

        if (!OSSL_PARAM_get_octet_string_ptr(p, (const void**)&tag, &taglen))
            return 0;

        gost_cipher_ctrl_fn ctrl =
            GET_MEMBER(GOST_cipher, gctx->descriptor, ctrl);
        if (ctrl && ctrl(gctx->cctx, EVP_CTRL_AEAD_GET_TAG, taglen, tag) > 0)
            return 1;
    }

    return 1;
}


static int cipher_set_ctx_params(void *vgctx, const OSSL_PARAM params[])
{
    GOST_CTX *gctx = vgctx;

    const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, "alg_id_param");
    if (p != NULL) {
        ASN1_TYPE* algidparam = NULL;
        const unsigned char* der = NULL;
        size_t derlen = 0;

        if (!OSSL_PARAM_get_octet_string_ptr(p, (const void**)&der, &derlen))
            return 0;

        if (!(algidparam = d2i_ASN1_TYPE(NULL, &der, (long)derlen)))
            return 0;

        gost_cipher_set_asn1_params_fn set_asn1 =
            GET_MEMBER(GOST_cipher, gctx->descriptor, set_asn1_parameters);
        int res = set_asn1(gctx->cctx, algidparam);

        ASN1_TYPE_free(algidparam);
        if (res <= 0)
            return 0;
        return 1;
    }

    p = OSSL_PARAM_locate_const(params, "key-mesh");
    if (p != NULL) {
        size_t key_mesh = 0;
        if (!OSSL_PARAM_get_size_t(p, &key_mesh))
            return 0;

        gost_cipher_ctrl_fn ctrl =
            GET_MEMBER(GOST_cipher, gctx->descriptor, ctrl);
        int res = ctrl ? ctrl(gctx->cctx, EVP_CTRL_KEY_MESH, (int)key_mesh, NULL) : -1;
        return res > 0;
    }

    p = OSSL_PARAM_locate_const(params, "padding");
    if (p != NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL) {
        size_t ivlen;
        if (!OSSL_PARAM_get_size_t(p, &ivlen))
            return 0;
        return 1;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        void* tag = NULL;
        size_t taglen = 0;

        if (!OSSL_PARAM_get_octet_string_ptr(p, (const void**)&tag, &taglen))
            return 0;

        gost_cipher_ctrl_fn ctrl =
            GET_MEMBER(GOST_cipher, gctx->descriptor, ctrl);
        if (ctrl && ctrl(gctx->cctx, EVP_CTRL_AEAD_SET_TAG, (int)taglen, tag) > 0)
            return 1;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLSTREE);
    if (p != NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLSTREE_MODE);
    if (p != NULL)
        return 1;

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

    gost_cipher_init_fn init =
        GET_MEMBER(GOST_cipher, gctx->descriptor, init);
    size_t expected_keylen = GET_MEMBER(GOST_cipher, gctx->descriptor, key_len);

    if (key && keylen != expected_keylen)
        return 0;

    int res = init(gctx->cctx, key, iv, 1);
    if (res <= 0) return 0;

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

    gost_cipher_init_fn init =
        GET_MEMBER(GOST_cipher, gctx->descriptor, init);
    size_t expected_keylen = GET_MEMBER(GOST_cipher, gctx->descriptor, key_len);

    if (key && keylen != expected_keylen)
        return 0;

    int res = init(gctx->cctx, key, iv, 0);
    if (res <= 0) return 0;

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

    gost_cipher_do_cipher_fn do_cipher =
        GET_MEMBER(GOST_cipher, gctx->descriptor, do_cipher);
    int res = do_cipher(gctx->cctx, out, in, inl);

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

#define MAKE_FUNCTIONS(name)                                     \
    static OSSL_FUNC_cipher_get_params_fn name##_get_params;            \
    static int name##_get_params(OSSL_PARAM *params)                    \
    {                                                                   \
        return cipher_get_params(&name, params);                        \
    }                                                                   \
    static OSSL_FUNC_cipher_newctx_fn name##_newctx;                    \
    static void* name##_newctx(void *provctx)                           \
    {                                                                   \
        return cipher_newctx(provctx, &name);                            \
    }                                                                   \
    const OSSL_DISPATCH name##_functions[] = {                          \
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

