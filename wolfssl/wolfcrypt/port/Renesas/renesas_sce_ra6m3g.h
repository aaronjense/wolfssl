#ifndef WOLFSSL_RENESAS_RA6M3G_SCE_H
#define WOLFSSL_RENESAS_RA6M3G_SCE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/ecc.h>

/* Renesas RA6M3G Secure Cryptogrpahy Engine (SCE) drivers for wolfCrypt */

/* General */
int wc_Renesas_SCE_init(void);
/* TRNG */
int wc_Renesas_GenerateSeed(byte* output, word32 sz);
/* SHA-2 */
int wc_Renesas_Sha256Transform(wc_Sha256*, const byte*);
/* AES */
#define AES_SCE_ENCRYPT (1) /* op for ECB/CBC */
#define AES_SCE_DECRYPT (2) /* op for ECB/CBC */
int wc_Renesas_AesCbc(Aes* aes, byte* out, const byte* in, word32 sz, int op);
int wc_Renesas_AesEcb(Aes* aes, byte* out, const byte* in, word32 sz, int op);
int wc_Renesas_AesCtrEncrypt(Aes* aes, byte* out, const byte* in, word32 sz);
/* ECC */
int wc_Renesas_EccGenerateKey(ecc_key* key);
int wc_Renesas_EccGenerateSign(ecc_key* key, const byte* hash, const word32 hashlen,
                               mp_int* r, mp_int* s);
int wc_Renesas_EccVerifySign(ecc_key* key, mp_int* r, mp_int* s,
                             const byte* hash, const word32 hashlen, int* res);
int wc_renesas_EccFormatArgs(const ecc_key* key, byte* domain, byte* gxy);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_RA6M3G_SCE_H */
