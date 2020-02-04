/* wolfssl_thread_entry.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#include <wolfssl/wolfcrypt/settings.h>
#include "wolfcrypt/test/test.h"
#include "wolfssl/wolfcrypt/port/Renesas/renesas_hw_sce.h"
#include <stdio.h>
#include "hw_sce_hash_private.h"

static int devId = INVALID_DEVID;
#define HEAP_HINT NULL


void wolfssl_thread_entry(void* pvParameters)
{
	int ret;

    FSP_PARAMETER_NOT_USED (pvParameters);
    initialise_monitor_handles();
    renesas_hw_sce_init();
    wolfcrypt_test(0);

//
//    /* BEGIN AES GCM TEST */
//    Aes enc;
//    Aes dec;
//
//    /*
//     * This is Test Case 16 from the document Galois/
//     * Counter Mode of Operation (GCM) by McGrew and
//     * Viega.
//     */
//    const byte p[] =
//    {
//        0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
//        0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
//        0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
//        0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
//        0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
//        0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
//        0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
//        0xba, 0x63, 0x7b, 0x39
//    };
//
//#if defined(HAVE_AES_DECRYPT) || defined(WOLFSSL_AES_256)
//    const byte a[] =
//    {
//        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
//        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
//        0xab, 0xad, 0xda, 0xd2
//    };
//#endif
//
//#ifdef WOLFSSL_AES_256
//    const byte k1[] =
//    {
//        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
//        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
//        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
//        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
//    };
//
//    const byte iv1[] =
//    {
//        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
//        0xde, 0xca, 0xf8, 0x88
//    };
//
//    const byte c1[] =
//    {
//        0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07,
//        0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
//        0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9,
//        0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
//        0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d,
//        0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
//        0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a,
//        0xbc, 0xc9, 0xf6, 0x62
//    };
//#endif /* WOLFSSL_AES_256 */
//
//    const byte t1[] =
//    {
//        0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68,
//        0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d, 0x55, 0x1b
//    };
//
//    /* FIPS, QAT and PIC32MZ HW Crypto only support 12-byte IV */
//#if !defined(HAVE_FIPS) && \
//        !defined(WOLFSSL_PIC32MZ_CRYPT) && \
//        !defined(FREESCALE_LTC) && !defined(FREESCALE_MMCAU) && \
//        !defined(WOLFSSL_XILINX_CRYPT) && !defined(WOLFSSL_AFALG_XILINX_AES) && \
//        !(defined(WOLF_CRYPTO_CB) && \
//            (defined(HAVE_INTEL_QA_SYNC) || defined(HAVE_CAVIUM_OCTEON_SYNC)))
//
//    #define ENABLE_NON_12BYTE_IV_TEST
//#ifdef WOLFSSL_AES_192
//    /* Test Case 12, uses same plaintext and AAD data. */
//    const byte k2[] =
//    {
//        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
//        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
//        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c
//    };
//
//    const byte iv2[] =
//    {
//        0x93, 0x13, 0x22, 0x5d, 0xf8, 0x84, 0x06, 0xe5,
//        0x55, 0x90, 0x9c, 0x5a, 0xff, 0x52, 0x69, 0xaa,
//        0x6a, 0x7a, 0x95, 0x38, 0x53, 0x4f, 0x7d, 0xa1,
//        0xe4, 0xc3, 0x03, 0xd2, 0xa3, 0x18, 0xa7, 0x28,
//        0xc3, 0xc0, 0xc9, 0x51, 0x56, 0x80, 0x95, 0x39,
//        0xfc, 0xf0, 0xe2, 0x42, 0x9a, 0x6b, 0x52, 0x54,
//        0x16, 0xae, 0xdb, 0xf5, 0xa0, 0xde, 0x6a, 0x57,
//        0xa6, 0x37, 0xb3, 0x9b
//    };
//
//    const byte c2[] =
//    {
//        0xd2, 0x7e, 0x88, 0x68, 0x1c, 0xe3, 0x24, 0x3c,
//        0x48, 0x30, 0x16, 0x5a, 0x8f, 0xdc, 0xf9, 0xff,
//        0x1d, 0xe9, 0xa1, 0xd8, 0xe6, 0xb4, 0x47, 0xef,
//        0x6e, 0xf7, 0xb7, 0x98, 0x28, 0x66, 0x6e, 0x45,
//        0x81, 0xe7, 0x90, 0x12, 0xaf, 0x34, 0xdd, 0xd9,
//        0xe2, 0xf0, 0x37, 0x58, 0x9b, 0x29, 0x2d, 0xb3,
//        0xe6, 0x7c, 0x03, 0x67, 0x45, 0xfa, 0x22, 0xe7,
//        0xe9, 0xb7, 0x37, 0x3b
//    };
//
//    const byte t2[] =
//    {
//        0xdc, 0xf5, 0x66, 0xff, 0x29, 0x1c, 0x25, 0xbb,
//        0xb8, 0x56, 0x8f, 0xc3, 0xd3, 0x76, 0xa6, 0xd9
//    };
//#endif /* WOLFSSL_AES_192 */
//#ifdef WOLFSSL_AES_128
//    /* The following is an interesting test case from the example
//     * FIPS test vectors for AES-GCM. IVlen = 1 byte */
//    const byte p3[] =
//    {
//        0x57, 0xce, 0x45, 0x1f, 0xa5, 0xe2, 0x35, 0xa5,
//        0x8e, 0x1a, 0xa2, 0x3b, 0x77, 0xcb, 0xaf, 0xe2
//    };
//
//    const byte k3[] =
//    {
//        0xbb, 0x01, 0xd7, 0x03, 0x81, 0x1c, 0x10, 0x1a,
//        0x35, 0xe0, 0xff, 0xd2, 0x91, 0xba, 0xf2, 0x4b
//    };
//
//    const byte iv3[] =
//    {
//        0xca
//    };
//
//    const byte c3[] =
//    {
//        0x6b, 0x5f, 0xb3, 0x9d, 0xc1, 0xc5, 0x7a, 0x4f,
//        0xf3, 0x51, 0x4d, 0xc2, 0xd5, 0xf0, 0xd0, 0x07
//    };
//
//    const byte a3[] =
//    {
//        0x40, 0xfc, 0xdc, 0xd7, 0x4a, 0xd7, 0x8b, 0xf1,
//        0x3e, 0x7c, 0x60, 0x55, 0x50, 0x51, 0xdd, 0x54
//    };
//
//    const byte t3[] =
//    {
//        0x06, 0x90, 0xed, 0x01, 0x34, 0xdd, 0xc6, 0x95,
//        0x31, 0x2e, 0x2a, 0xf9, 0x57, 0x7a, 0x1e, 0xa6
//    };
//#endif /* WOLFSSL_AES_128 */
//#ifdef WOLFSSL_AES_256
//    int ivlen;
//#endif
//#endif
//
//    byte resultT[sizeof(t1)];
//    byte resultP[sizeof(p) + AES_BLOCK_SIZE];
//    byte resultC[sizeof(p) + AES_BLOCK_SIZE];
//    int  result;
//#ifdef WOLFSSL_AES_256
//    int  alen;
//    #ifndef WOLFSSL_AFALG_XILINX_AES
//    int  plen;
//    #endif
//#endif
//
//#if !defined(BENCH_EMBEDDED)
//    #ifndef BENCH_AESGCM_LARGE
//        #define BENCH_AESGCM_LARGE 1024
//    #endif
//    byte large_input[BENCH_AESGCM_LARGE];
//    byte large_output[BENCH_AESGCM_LARGE + AES_BLOCK_SIZE];
//    byte large_outdec[BENCH_AESGCM_LARGE];
//
//    XMEMSET(large_input, 0, sizeof(large_input));
//    XMEMSET(large_output, 0, sizeof(large_output));
//    XMEMSET(large_outdec, 0, sizeof(large_outdec));
//#endif
//
//    XMEMSET(resultT, 0, sizeof(resultT));
//    XMEMSET(resultC, 0, sizeof(resultC));
//    XMEMSET(resultP, 0, sizeof(resultP));
//
//    if (wc_AesInit(&enc, HEAP_HINT, devId) != 0) {
//        printf("-5699\n");
//        printf("\n");
//    }
//
//    if (wc_AesInit(&dec, HEAP_HINT, devId) != 0) {
//        printf("-5700\n");
//        printf("\n");
//
//    }
//
//    result = wc_AesGcmSetKey(&enc, k1, sizeof(k1));
//    if (result != 0) {
//        printf("-5701\n");
//        printf("\n");
//
//    }
//
//    /* AES-GCM encrypt and decrypt both use AES encrypt internally */
//    result = wc_AesGcmEncrypt(&enc, resultC, p, sizeof(p), iv1, sizeof(iv1),
//                                        resultT, sizeof(resultT), a, sizeof(a));
//
//    printf("ResultC\n");
//    for (int i = 0; i < XSTRLEN(resultC); i++) {
//    	printf("%X ", resultC[i]);
//    }
//    printf("\n\n");
//
//    printf("ResultT\n");
//    for (int i = 0; i < XSTRLEN(resultC); i++) {
//    	printf("%X ", resultT[i]);
//    }
//    printf("\n\n");
//
//    if (result != 0) {
//        printf("-5702\n");
//        printf("\n");
//    }
//
//#if defined(WOLFSSL_ASYNC_CRYPT)
//    result = wc_AsyncWait(result, &enc.asyncDev, WC_ASYNC_FLAG_NONE);
//#endif
//    if (result != 0) {
//        printf("-5703\n");
//        printf("\n");
//    }
//    if (XMEMCMP(c1, resultC, sizeof(c1))) {
//        printf("-5704\n");
//        printf("\n");
//    }
//    if (XMEMCMP(t1, resultT, sizeof(resultT))) {
//        printf("-5705\n");
//        printf("\n");
//    }
//
//
//    result = wc_AesGcmSetKey(&dec, k1, sizeof(k1));
//    if (result != 0) {
//        printf("-5706\n");
//        printf("\n");
//    }
//
//    result = wc_AesGcmDecrypt(&dec, resultP, resultC, sizeof(c1),
//                      iv1, sizeof(iv1), resultT, sizeof(resultT), a, sizeof(a));
//#if defined(WOLFSSL_ASYNC_CRYPT)
//    result = wc_AsyncWait(result, &dec.asyncDev, WC_ASYNC_FLAG_NONE);
//#endif
//    if (result != 0) {
//        printf("-5707\n");
//        printf("\n");
//    }
//    if (XMEMCMP(p, resultP, sizeof(p))) {
//        printf("-5708\n");
//        printf("\n");
//    }

    /* END AES GCM TEST */

    while(1);
}
