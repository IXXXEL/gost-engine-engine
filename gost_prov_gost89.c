#include <string.h>
#include <openssl/objects.h>
#include "gost_lcl.h"

extern gost_subst_block Gost28147_TestParamSet;
extern gost_subst_block Gost28147_CryptoProParamSetA;

static const gost_subst_block* get_sblock_by_nid(int nid) {
    switch (nid) {
        case NID_id_Gost28147_89:
            return &Gost28147_CryptoProParamSetA;
        default:
            return NULL;
    }
}

int gost_89_cfb_init(struct ossl_gost_cipher_ctx *c, const unsigned char *key, const unsigned char *iv, int enc)
{
    if (!c) return 0;

    const gost_subst_block *sblock = get_sblock_by_nid(NID_id_Gost28147_89);
    if (!sblock) return 0;

    gost_init(&c->cctx, sblock);

    if (key) {
        gost_key(&c->cctx, key);
    }

    if (iv) {
        memcpy(c->iv, iv, 8);
    } else {
        memset(c->iv, 0, 8);
    }

    c->count = 0;
    c->encrypting = enc;

    return 1;
}

int gost_89_cfb_do(struct ossl_gost_cipher_ctx *c, unsigned char *out, const unsigned char *in, size_t inl)
{
    if (!c || !in || !out) return 0;

    const int encrypting = c->encrypting;
    size_t i, j;

    if (c->count > 0) {
        if (c->count == 8) {
            gostcrypt(&c->cctx, c->iv, c->buf);
        }

        for (j = c->count, i = 0; j < 8 && i < inl; ++j, ++i) {
            unsigned char pt = *in++;
            unsigned char ct = c->buf[j] ^ pt;
            *out++ = ct;

            if (encrypting) {
                memcpy(c->buf + 8 + j, &pt, 1);
            } else {
                memcpy(c->buf + 8 + j, &ct, 1);
            }
        }

        if (j == 8) {
            memcpy(c->iv, c->buf + 8, 8);
            c->count = 0;
        } else {
            c->count = j;
            return 1;
        }
    }

    while (inl >= 8) {
        gostcrypt(&c->cctx, c->iv, c->buf);

        if (encrypting) {
            for (j = 0; j < 8; ++j) {
                out[j] = c->buf[j] ^ in[j];
            }
            memcpy(c->iv, out, 8);
        } else {
            for (j = 0; j < 8; ++j) {
                out[j] = c->buf[j] ^ in[j];
            }
            memcpy(c->iv, in, 8);
        }

        in += 8;
        out += 8;
        inl -= 8;
    }

    if (inl > 0) {
        gostcrypt(&c->cctx, c->iv, c->buf);

        for (j = 0; j < inl; ++j) {
            unsigned char pt = in[j];
            unsigned char ct = c->buf[j] ^ pt;
            out[j] = ct;

            if (encrypting) {
                memcpy(c->buf + 8 + j, &pt, 1);
            } else {
                memcpy(c->buf + 8 + j, &ct, 1);
            }
        }

        c->count = inl;
    } else {
        c->count = 0;
    }

    return 1;
}

void gost_89_cfb_cleanup(struct ossl_gost_cipher_ctx *c)
{
    if (!c) return;
    OPENSSL_cleanse(c, sizeof(struct ossl_gost_cipher_ctx));
}
