#ifndef GOST_PROV_GOST89_COMMON_H
#define GOST_PROV_GOST89_COMMON_H

#include "gost_prov_lcl.h"

void gost_cipher_cleanup(void *cipher_data);
int gost_cipher_ctl(void *cipher_data, int type, int arg, void *ptr);

#endif
