#ifndef GOST_PROV_GOST89_H
#define GOST_PROV_GOST89_H

#include "gost_lcl.h"

int gost_89_cfb_init(struct ossl_gost_cipher_ctx *c, const unsigned char *key, const unsigned char *iv, int enc);
int gost_89_cfb_do(struct ossl_gost_cipher_ctx *c, unsigned char *out, const unsigned char *in, size_t inl);
void gost_89_cfb_cleanup(struct ossl_gost_cipher_ctx *c);

#endif