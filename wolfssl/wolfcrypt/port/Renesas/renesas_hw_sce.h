#ifndef WOLFSSL_RENESAS_RA6M3G_SCE_H
#define WOLFSSL_RENESAS_RA6M3G_SCE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/sha256.h"

/* Public Functions */
int renesas_hw_sce_init(void);
int renesas_sce_Sha256Update(wc_Sha256*, const byte*, word32);
int renesas_sce_Sha256Final(wc_Sha256*, byte*);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_RA6M3G_SCE_H */
