
#include <wolfssl/wolfcrypt/settings.h>
#include "wolfssl/wolfcrypt/port/Renesas/renesas_hw_sce.h"
#include "common/hw_sce_common.h"
#include "hw_sce_private.h"
#include "hw_sce_hash_private.h"
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
 #if defined(BIG_ENDIAN_ORDER)
        HW_SCE_EndianSetBig();
 #else
        HW_SCE_EndianSetLittle();
 #endif
    } else {
        return WOLFSSL_FAILURE;
    }

    return WOLFSSL_SUCCESS;
}

static inline void AddLength(wc_Sha256* sha256, word32 len)
{
    word32 tmp = sha256->loLen;
    if ((sha256->loLen += len) < tmp) {
        sha256->hiLen++;                       /* carry low to high */
    }
}

static inline word32 rotlFixed(word32 x, word32 y)
{
    return (x << y) | (x >> (sizeof(y) * 8 - y));
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

int renesas_sce_Sha256Update(wc_Sha256* sha256, const byte* data, word32 len) {
	int ret;
	word32 blocksLen;
    byte* local;

	if (sha256 == NULL || (data == NULL && len > 0)) {
		return BAD_FUNC_ARG;
	}

	if (data == NULL && len == 0) {
		/* valid, but do nothing */
		return 0;
	}

	/* check that internal buffLen is valid */
	if (sha256->buffLen >= WC_SHA256_BLOCK_SIZE) {
	    return BUFFER_E;
	}

    /* add length for final */
    AddLength(sha256, len);

    local = (byte*)sha256->buffer;

    /* process any remainder from previous operation */
    if (sha256->buffLen > 0) {
        blocksLen = min(len, WC_SHA256_BLOCK_SIZE - sha256->buffLen);
        XMEMCPY(&local[sha256->buffLen], data, blocksLen);

        sha256->buffLen += blocksLen;
        data            += blocksLen;
        len             -= blocksLen;

        if (sha256->buffLen == WC_SHA256_BLOCK_SIZE) {
		#if defined(LITTLE_ENDIAN_ORDER) && !defined(FREESCALE_MMCAU_SHA)
			#if defined(HAVE_INTEL_AVX1) || defined(HAVE_INTEL_AVX2)
			if (!IS_INTEL_AVX1(intel_flags) && !IS_INTEL_AVX2(intel_flags))
			#endif
			{
				ByteReverseWords(sha256->buffer, sha256->buffer,
					WC_SHA256_BLOCK_SIZE);
			}
		#endif
			 /* Byte alignment handled in function if required */
			ret = HW_SCE_SHA256_UpdateHash((const uint32_t*) local,
									 (uint32_t) 16,
									 (uint32_t*) sha256->digest);

			if (ret != FSP_SUCCESS) {
				printf("Error: HW_SCE_SHa256_UpdateHash");
				printf("\n");
			}

			if (ret == 0)
				sha256->buffLen = 0;
			else
				len = 0; /* error */
        }
    }

    while (len >= WC_SHA256_BLOCK_SIZE) {
        word32* local32 = sha256->buffer;
        /* optimization to avoid memcpy if data pointer is properly aligned */
        /* Intel transform function requires use of sha256->buffer */
        /* Little Endian requires byte swap, so can't use data directly */

        XMEMCPY(local32, data, WC_SHA256_BLOCK_SIZE);
		#if defined(LITTLE_ENDIAN_ORDER) && !defined(FREESCALE_MMCAU_SHA)
			#if defined(HAVE_INTEL_AVX1) || defined(HAVE_INTEL_AVX2)
			if (!IS_INTEL_AVX1(intel_flags) && !IS_INTEL_AVX2(intel_flags))
			#endif
			{
				ByteReverseWords(local32, local32,
					WC_SHA256_BLOCK_SIZE);
			}
		#endif
		ret = HW_SCE_SHA256_UpdateHash((const uint32_t*) local32,
								 (uint32_t) 16,
								 (uint32_t*) sha256->digest);

		if (ret != FSP_SUCCESS) {
			printf("Error: HW_SCE_SHa256_UpdateHash");
			printf("\n");
		}

        data += WC_SHA256_BLOCK_SIZE;
        len  -= WC_SHA256_BLOCK_SIZE;

        if (ret != 0)
            break;
    }

	/* save remainder */
	if (len > 0) {
		XMEMCPY(local, data, len);
  		sha256->buffLen = len;
	}

	return ret;
}

int renesas_sce_Sha256Final(wc_Sha256* sha256, byte* hash)
{
    int ret;
    byte* local;

    if (sha256 == NULL) {
        return BAD_FUNC_ARG;
    }

    local = (byte*)sha256->buffer;
    local[sha256->buffLen++] = 0x80; /* add 1 */

    /* pad with zeros */
    if (sha256->buffLen > WC_SHA256_PAD_SIZE) {
        XMEMSET(&local[sha256->buffLen], 0,
            WC_SHA256_BLOCK_SIZE - sha256->buffLen);
        sha256->buffLen += WC_SHA256_BLOCK_SIZE - sha256->buffLen;

    #if defined(LITTLE_ENDIAN_ORDER) && !defined(FREESCALE_MMCAU_SHA)
        #if defined(HAVE_INTEL_AVX1) || defined(HAVE_INTEL_AVX2)
        if (!IS_INTEL_AVX1(intel_flags) && !IS_INTEL_AVX2(intel_flags))
        #endif
        {
 //           ByteReverseWords(sha256->buffer, sha256->buffer,
 //                                                 WC_SHA256_BLOCK_SIZE);
        }
    #endif

		ret = HW_SCE_SHA256_UpdateHash((const uint32_t*) local,
								 (uint32_t) 16,
								 (uint32_t*) sha256->digest);

        if (ret != 0)
            return ret;

        sha256->buffLen = 0;
    }
    XMEMSET(&local[sha256->buffLen], 0,
        WC_SHA256_PAD_SIZE - sha256->buffLen);

    /* put lengths in bits */
    sha256->hiLen = (sha256->loLen >> (8 * sizeof(sha256->loLen) - 3)) +
                                                     (sha256->hiLen << 3);
    sha256->loLen = sha256->loLen << 3;

    /* store lengths */
#if defined(LITTLE_ENDIAN_ORDER) && !defined(FREESCALE_MMCAU_SHA)
    #if defined(HAVE_INTEL_AVX1) || defined(HAVE_INTEL_AVX2)
    if (!IS_INTEL_AVX1(intel_flags) && !IS_INTEL_AVX2(intel_flags))
    #endif
    {
        ByteReverseWords(sha256->buffer, sha256->buffer,
            WC_SHA256_BLOCK_SIZE);
    }
#endif
    /* ! length ordering dependent on digest endian type ! */
    XMEMCPY(&local[WC_SHA256_PAD_SIZE], &sha256->hiLen, sizeof(word32));
    XMEMCPY(&local[WC_SHA256_PAD_SIZE + sizeof(word32)], &sha256->loLen,
            sizeof(word32));

	ret = HW_SCE_SHA256_UpdateHash((const uint32_t*) local,
							 (uint32_t) 16,
							 (uint32_t*) sha256->digest);

    XMEMCPY(hash, sha256->digest, WC_SHA256_DIGEST_SIZE);

    return ret;
}
