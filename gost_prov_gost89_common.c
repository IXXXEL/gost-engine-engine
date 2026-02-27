#include "gost_prov_gost89_common.h"

void gost_cipher_cleanup(void *cipher_data)
{
    GOST_Prov_Cipher_CTX *ctx = cipher_data;
    if (!ctx) return;

    gost_destroy(&ctx->cctx);
    memset(ctx, 0, sizeof(*ctx));
}

int gost_cipher_ctl(void *cipher_data, int type, int arg, void *ptr)
{
    return -1;
}
