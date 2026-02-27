#ifndef GOST_PROV_GOST89_H
#define GOST_PROV_GOST89_H

#include "gost_prov_gost89_common.h"

int gost89_cipher_init_cfb(void *cipher_data,
                     const unsigned char *key,
                     const unsigned char *iv,
                     int enc);
int gost89_cipher_do_cfb(void *cipher_data, unsigned char *out,
                   const unsigned char *in, size_t inl);
int gost89_set_asn1_parameters(void *cipher_data, ASN1_TYPE *params);
int gost89_get_asn1_parameters(void *cipher_data, ASN1_TYPE *params);

GOST_Prov_Cipher Gost28147_89_cipher = {
    .nid = NID_id_Gost28147_89,
    .block_size = 1,
    .flags = EVP_CIPH_CFB_MODE | EVP_CIPH_NO_PADDING,
    .init = gost89_cipher_init_cfb,
    .do_cipher = gost89_cipher_do_cfb,
    .cleanup = gost_cipher_cleanup,
    .set_asn1_params = gost89_set_asn1_parameters,
    .get_asn1_params = gost89_get_asn1_parameters,
    .ctrl = gost_cipher_ctl,
};

#endif
