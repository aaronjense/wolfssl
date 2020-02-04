#ifndef WOLFSSL_RENESAS_RA6M3G_SCE_H
#define WOLFSSL_RENESAS_RA6M3G_SCE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/aes.h"

/* Public Functions */
int renesas_hw_sce_init(void);
int renesas_sce_Sha256Transform(wc_Sha256*, const byte*);
int renesas_sce_Sha256Final(wc_Sha256*, byte*);
int wc_RenesasAesCbcEncrypt(Aes* aes, byte* out, const byte* in, word32 sz);
int wc_RenesasAesCbcDecrypt(Aes* aes, byte* out, const byte* in, word32 sz);
int wc_RenesasAesEcbEncrypt(Aes* aes, byte* out, const byte* in, word32 sz);
int wc_RenesasAesEcbDecrypt(Aes* aes, byte* out, const byte* in, word32 sz);

void print_sha256(wc_Sha256* sha256);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_RA6M3G_SCE_H */
