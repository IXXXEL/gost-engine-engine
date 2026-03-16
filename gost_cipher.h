#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/asn1.h>
#include "utils_inheritance.h"
#include "e_gost_err.h"
#include "gost89.h"

typedef struct gost_cipher_st GOST_cipher;
typedef struct gost_cipher_ctx_st GOST_CIPHER_CTX;

typedef int (*gost_cipher_init_fn)(GOST_CIPHER_CTX *, const unsigned char *key,
                                   const unsigned char *iv, int enc);
typedef int (*gost_cipher_do_cipher_fn)(GOST_CIPHER_CTX *,
                                        unsigned char *out,
                                        const unsigned char *in,
                                        size_t len);
typedef void (*gost_cipher_cleanup_fn)(GOST_CIPHER_CTX *);
typedef int (*gost_cipher_set_asn1_params_fn)(GOST_CIPHER_CTX *, ASN1_TYPE *);
typedef int (*gost_cipher_get_asn1_params_fn)(GOST_CIPHER_CTX *, ASN1_TYPE *);
typedef int (*gost_cipher_ctrl_fn)(GOST_CIPHER_CTX *, int type, int arg, void *ptr);
typedef void (*gost_cipher_static_init_fn)(const GOST_cipher*);
typedef void (*gost_cipher_static_deinit_fn)(const GOST_cipher*);

struct gost_cipher_ctx_st {
    const GOST_cipher* cipher_desc;
    size_t algctx_size;
    void* algctx;

    unsigned char iv[8];
    unsigned char orig_iv[8];
    unsigned char buf[16];
    size_t count;
    int encrypting;
};

struct gost_cipher_info {
    int nid;
    gost_subst_block *sblock;
    int key_meshing;
};

typedef struct {
    ASN1_OCTET_STRING *iv;
    ASN1_OBJECT *enc_param_set;
} GOST_CIPHER_PARAMS;

struct gost_cipher_st {
    DECL_BASE(const struct gost_cipher_st);

    DECL_MEMBER(int, nid);
    DECL_MEMBER(int, block_size);
    DECL_MEMBER(int, key_len);
    DECL_MEMBER(int, iv_len);
    DECL_MEMBER(size_t, algctx_size);
    DECL_MEMBER(int, flags);
    DECL_MEMBER(gost_cipher_init_fn, init);
    DECL_MEMBER(gost_cipher_do_cipher_fn, do_cipher);
    DECL_MEMBER(gost_cipher_cleanup_fn, cleanup);
    DECL_MEMBER(gost_cipher_set_asn1_params_fn, set_asn1_parameters);
    DECL_MEMBER(gost_cipher_get_asn1_params_fn, get_asn1_parameters);
    DECL_MEMBER(gost_cipher_ctrl_fn, ctrl);
    DECL_MEMBER(gost_cipher_static_init_fn, static_init);
    DECL_MEMBER(gost_cipher_static_deinit_fn, static_deinit);
};

IMPL_MEMBER_ACCESSOR(GOST_cipher, int, nid);
IMPL_MEMBER_ACCESSOR(GOST_cipher, int, block_size);
IMPL_MEMBER_ACCESSOR(GOST_cipher, int, key_len);
IMPL_MEMBER_ACCESSOR(GOST_cipher, int, iv_len);
IMPL_MEMBER_ACCESSOR(GOST_cipher, size_t, algctx_size);
IMPL_MEMBER_ACCESSOR(GOST_cipher, int, flags);

IMPL_MEMBER_ACCESSOR(GOST_cipher, gost_cipher_init_fn, init);
IMPL_MEMBER_ACCESSOR(GOST_cipher, gost_cipher_do_cipher_fn, do_cipher);
IMPL_MEMBER_ACCESSOR(GOST_cipher, gost_cipher_cleanup_fn, cleanup);

IMPL_MEMBER_ACCESSOR(GOST_cipher, gost_cipher_set_asn1_params_fn, set_asn1_parameters);
IMPL_MEMBER_ACCESSOR(GOST_cipher, gost_cipher_get_asn1_params_fn, get_asn1_parameters);
IMPL_MEMBER_ACCESSOR(GOST_cipher, gost_cipher_ctrl_fn, ctrl);

IMPL_MEMBER_ACCESSOR(GOST_cipher, gost_cipher_static_init_fn, static_init);
IMPL_MEMBER_ACCESSOR(GOST_cipher, gost_cipher_static_deinit_fn, static_deinit);

GOST_CIPHER_CTX* gost_cipher_ctx_new(void);
void gost_cipher_ctx_free(GOST_CIPHER_CTX *ctx);
int gost_cipher_ctx_copy(GOST_CIPHER_CTX *out, const GOST_CIPHER_CTX *in);

static inline void gost_cipher_ctx_reset(GOST_CIPHER_CTX *ctx) {
    memset(ctx->iv, 0, sizeof(ctx->iv));
    memset(ctx->orig_iv, 0, sizeof(ctx->orig_iv));
    memset(ctx->buf, 0, sizeof(ctx->buf));
    ctx->count = 0;
    ctx->encrypting = -1;
}

static inline void* gost_cipher_algctx(const GOST_CIPHER_CTX *ctx) {
    return ctx->algctx;
}

static inline unsigned char* gost_cipher_get_iv(GOST_CIPHER_CTX *ctx) {
    return ctx->iv;
}

static inline const unsigned char* gost_cipher_get_orig_iv(const GOST_CIPHER_CTX *ctx) {
    return ctx->orig_iv;
}

static inline unsigned char* gost_cipher_get_buf(GOST_CIPHER_CTX *ctx) {
    return ctx->buf + 8;
}

static inline int gost_cipher_is_encrypting(const GOST_CIPHER_CTX *ctx) {
    return ctx->encrypting;
}

static inline void gost_cipher_set_num(GOST_CIPHER_CTX *ctx, size_t n) {
    ctx->count = n;
}

static inline size_t gost_cipher_get_num(const GOST_CIPHER_CTX *ctx) {
    return ctx->count;
}

int gost_cipher_set_param(GOST_CIPHER_CTX *ctx, int nid);
int gost_cipher_get_iv_len(const GOST_CIPHER_CTX *ctx);

const char* gost_cipher_get0_name(const GOST_cipher *desc);

# define GOST_PARAM_CRYPT_PARAMS 0
