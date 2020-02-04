
#include <wolfssl/wolfcrypt/settings.h>
#include "wolfssl/wolfcrypt/port/Renesas/renesas_hw_sce.h"
#include "common/hw_sce_common.h"
#include "hw_sce_private.h"
#include "hw_sce_hash_private.h"
#include "hw_sce_aes_private.h"
#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include <stdio.h>

static inline word32 min(word32 a, word32 b)
{
    return a > b ? b : a;
}

int renesas_hw_sce_init(void) {
    fsp_err_t fret;

    HW_SCE_PowerOn();

    HW_SCE_SoftReset();

    fret = HW_SCE_Initialization1();
    if (FSP_SUCCESS == fret) {
        fret = HW_SCE_Initialization2();
    } else {
        return WOLFSSL_FAILURE;
    }

    if (FSP_SUCCESS == fret) {
        fret = HW_SCE_secureBoot();
    } else {
        return WOLFSSL_FAILURE;
    }

    if (FSP_SUCCESS == fret) {
    	HW_SCE_EndianSetLittle();
    } else {
        return WOLFSSL_FAILURE;
    }

    return WOLFSSL_SUCCESS;
}

int renesas_sce_Sha256Transform(wc_Sha256* sha256, const byte* data) {
	int ret;
	(void) data;

	if (sha256 == NULL)
		ret = WOLFSSL_FAILURE;

	if (ret != WOLFSSL_FAILURE)
		ret = wolfSSL_CryptHwMutexLock();

    HW_SCE_EndianSetBig();
	if (ret == 0) {
		ret = HW_SCE_SHA256_UpdateHash((const uint32_t*) sha256->buffer,
							 (uint32_t) WC_SHA256_BLOCK_SIZE  / sizeof(word32),
							 (uint32_t*) sha256->digest);
	}

    wolfSSL_CryptHwMutexUnLock();

	return ret;
}

static inline void XorWords(wolfssl_word* r, const wolfssl_word* a, word32 n)
{
    word32 i;

    for (i = 0; i < n; i++) r[i] ^= a[i];
}

static inline void xorbuf(void* buf, const void* mask, word32 count)
{
    if (((wolfssl_word)buf | (wolfssl_word)mask | count) % WOLFSSL_WORD_SIZE == 0)
        XorWords( (wolfssl_word*)buf,
                  (const wolfssl_word*)mask, count / WOLFSSL_WORD_SIZE);
    else {
        word32 i;
        byte*       b = (byte*)buf;
        const byte* m = (const byte*)mask;

        for (i = 0; i < count; i++) b[i] ^= m[i];
    }
}

static inline word32 rotlFixed(word32 x, word32 y)
{
    return (x << y) | (x >> (sizeof(y) * 8 - y));
}


static inline word32 rotrFixed(word32 x, word32 y)
{
    return (x >> y) | (x << (sizeof(y) * 8 - y));
}

static inline word32 ByteReverseWord32(word32 value)
{
#ifdef PPC_INTRINSICS
/* PPC: load reverse indexed instruction */
return (word32)__lwbrx(&value,0);
#elif defined(__ICCARM__)
return (word32)__REV(value);
#elif defined(KEIL_INTRINSICS)
return (word32)__rev(value);
#elif defined(WOLF_ALLOW_BUILTIN) && \
    defined(__GNUC_PREREQ) && __GNUC_PREREQ(4, 3)
return (word32)__builtin_bswap32(value);
#elif defined(FAST_ROTATE)
/* 5 instructions with rotate instruction, 9 without */
return (rotrFixed(value, 8U) & 0xff00ff00) |
       (rotlFixed(value, 8U) & 0x00ff00ff);
#else
/* 6 instructions with rotate instruction, 8 without */
value = ((value & 0xFF00FF00) >> 8) | ((value & 0x00FF00FF) << 8);
return rotlFixed(value, 16U);
#endif
}


static inline void ByteReverseWords(word32* out, const word32* in,
                                word32 byteCount)
{
word32 count = byteCount/(word32)sizeof(word32), i;

for (i = 0; i < count; i++)
    out[i] = ByteReverseWord32(in[i]);

}

#define AESNI_ALIGN 16

int wc_RenesasAesCbcEncrypt(Aes* aes, byte* out, const byte* in, word32 sz) {
	word32 keySize = 0;
    word32 num_words = (sz / sizeof(word32));
    int ret;

    /* hardware fails on input that is not a multiple of AES block size */
    if (sz % AES_BLOCK_SIZE != 0) {
        return BAD_FUNC_ARG;
    }

    ret = wc_AesGetKeySize(aes, &keySize);

	ret = wolfSSL_CryptHwMutexLock();

#ifdef WOLFSSL_AES_128
	ret = HW_SCE_AES_128CbcEncrypt((const uint32_t*)  aes->key,
									(const uint32_t*) aes->reg,
									(const uint32_t)  num_words,
									(const uint32_t*) in,
									(uint32_t*) out,
									(uint32_t*) aes->reg);
#endif

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}

int wc_RenesasAesCbcDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
	word32 keySize = 0;
    word32 num_words = (sz / sizeof(word32));
    int ret;

    /* hardware fails on input that is not a multiple of AES block size */
    if (sz % AES_BLOCK_SIZE != 0) {
        return BAD_FUNC_ARG;
    }
    ret = wc_AesGetKeySize(aes, &keySize);

    if (keySize == 16) {
		ret =  HW_SCE_AES_128CbcDecrypt((const uint32_t *) aes->key,
									    (const uint32_t *) aes->reg,
									    (const uint32_t)   num_words,
									    (const uint32_t *) in,
									    (uint32_t *) out,
									    (uint32_t *) aes->reg);
    }

    return ret;
}

int wc_RenesasAesEcbEncrypt(Aes* aes, byte* out, const byte* in, word32 sz) {
	word32 keySize = 0;
    word32 num_words = (sz / sizeof(word32));
    int ret;

    /* hardware fails on input that is not a multiple of AES block size */
    if (sz % AES_BLOCK_SIZE != 0) {
        return BAD_FUNC_ARG;
    }

    wc_AesGetKeySize(aes, &keySize);

	ret = wolfSSL_CryptHwMutexLock();

	if (keySize == 16) {
		ret = HW_SCE_AES_128EcbEncrypt((const uint32_t*)  aes->key,
										(const uint32_t)  num_words,
										(const uint32_t*) in,
										(uint32_t*) out);
	} else if (keySize == 32) {
		ret = HW_SCE_AES_256EcbEncrypt((const uint32_t*)  aes->key,
										(const uint32_t)  num_words,
										(const uint32_t*) in,
										(uint32_t*) out);
	}

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}

int wc_RenesasAesEcbDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
	word32 keySize = 0;
    word32 num_words = (sz / sizeof(word32));
    int ret;

    /* hardware fails on input that is not a multiple of AES block size */
    if (sz % AES_BLOCK_SIZE != 0) {
        return BAD_FUNC_ARG;
    }

	ret =  HW_SCE_AES_128EcbDecrypt((const uint32_t *) aes->key,
									(const uint32_t)   num_words,
									(const uint32_t *) in,
									(uint32_t *) out);

    return ret;
}
