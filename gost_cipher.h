#pragma once

#include <openssl/core.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include "e_gost_err.h"
#include "gost89.h"

# define GOST_PARAM_PBE_PARAMS 1

#define TPL(st,field) ( \
    ((st)->field) ? ((st)->field) : TPL_VAL(st,field) \
)

#define TPL_VAL(st,field) ( \
    ((st)->template ? (st)->template->field : 0) \
)

/* Structure to map parameter NID to S-block */
struct gost_cipher_info {
    int nid;
    gost_subst_block *sblock;
    int key_meshing;
};

typedef struct {
    gost_ctx cctx;
    unsigned char iv[8];
    unsigned char orig_iv[8];
    unsigned char buf[16];
    void *app_data;
    size_t count;
    int encrypting;
    int paramNID;  
    unsigned int key_meshing;
    const struct gost_cipher_st *cipher_desc;
} GOST_CIPHER_CTX;


typedef struct gost_cipher_st {
    struct gost_cipher_st *template;
    int nid;
    int block_size;
    int key_len;
    int iv_len;
    int flags;
    int ctx_size;
    int (*init)(void *GOST_CIPHER_CTX, const unsigned char *key,
            const unsigned char *iv, int enc);
    int (*do_cipher)(void *GOST_CIPHER_CTX, unsigned char *out,
                     const unsigned char *in, size_t inl);
    void (*cleanup)(void *cipher_data);
    int (*set_asn1_parameters)(void *cipher_data, ASN1_TYPE *params);
    int (*get_asn1_parameters)(void *cipher_data, ASN1_TYPE *params);
    int (*ctrl)(void *cipher_data, int type, int arg, void *ptr);

    gost_subst_block *sblock;
} GOST_cipher;

typedef struct {
    ASN1_OCTET_STRING *iv;
    ASN1_OBJECT *enc_param_set;
} GOST_CIPHER_PARAMS;

DECLARE_ASN1_FUNCTIONS(GOST_CIPHER_PARAMS)
unsigned char *gost_cipher_get_iv(GOST_CIPHER_CTX *ctx);//EVP_CIPHER_CTX_iv_noconst
unsigned char *gost_cipher_get_original_iv(GOST_CIPHER_CTX *ctx);//EVP_CIPHER_CTX_original_iv
unsigned char *gost_cipher_get_buf(GOST_CIPHER_CTX *ctx);//EVP_CIPHER_CTX_buf_noconst
int gost_cipher_is_encrypting(const GOST_CIPHER_CTX *ctx);//EVP_CIPHER_CTX_encrypting
void gost_cipher_set_num(GOST_CIPHER_CTX *ctx, size_t n);//EVP_CIPHER_CTX_set_num
size_t gost_cipher_get_num(const GOST_CIPHER_CTX *ctx);//EVP_CIPHER_CTX_num
int gost_cipher_get_iv_len(const GOST_CIPHER_CTX *ctx);//EVP_CIPHER_CTX_iv_length
int gost_cipher_get_key_len(const GOST_CIPHER_CTX *ctx);//EVP_CIPHER_CTX_key_length
void *gost_cipher_get_app_data(const GOST_CIPHER_CTX *ctx);//EVP_CIPHER_CTX_get_app_data
void gost_cipher_set_app_data(GOST_CIPHER_CTX *ctx, void *data);//EVP_CIPHER_CTX_set_app_data
GOST_CIPHER_CTX *gost_cipher_ctx_new(void);//EVP_CIPHER_CTX_new
void gost_cipher_ctx_free(GOST_CIPHER_CTX *ctx);//EVP_CIPHER_CTX_free
const char *gost_cipher_get0_name(GOST_cipher *desc);//EVP_CIPHER_name
unsigned long gost_cipher_get_flags(GOST_cipher *desc);//EVP_CIPHER_get_flags
int gost_cipher_get_block_size(GOST_cipher *desc);//EVP_CIPHER_get_block_size
int gost_cipher_ctx_copy(GOST_CIPHER_CTX *out, const GOST_CIPHER_CTX *in);//EVP_CIPHER_CTX_copy
void gost_cipher_ctx_reset(GOST_CIPHER_CTX *ctx);//
