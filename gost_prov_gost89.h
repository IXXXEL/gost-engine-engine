#ifndef GOST_PROV_GOST89_H
#define GOST_PROV_GOST89_H

#include "gost_prov_gost89_common.h"

int gost89_cipher_init_cfb(void *cipher_data,
                     const unsigned char *key,
                     const unsigned char *iv,
                     int enc);
int gost89_cipher_do_cfb(void *cipher_data, unsigned char *out,
                   const unsigned char *in, size_t inl);
int gost89_set_asn1_params(void *cipher_data, ASN1_TYPE *params);
int gost89_get_asn1_params(void *cipher_data, ASN1_TYPE *params);

extern GOST_Prov_Cipher Gost28147_89_cipher;

#endif
