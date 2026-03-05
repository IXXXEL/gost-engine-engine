#pragma once
#include "gost_cipher.h"

int gost_cipher_set_param(GOST_CIPHER_CTX *ctx, int nid);

extern const GOST_cipher Gost28147_89_cipher;