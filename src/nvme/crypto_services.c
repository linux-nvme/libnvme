// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2025 Western Digital Corporation or its affiliates.
 *
 * Authors: Chianjeb Mondal <chiranjeb.mondal@wdc.com>
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <malloc.h>

#ifdef CONFIG_OPENSSL
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#endif  

#include "cleanup.h"
#include "private.h"
#include "log.h"
#include "linux.h"

#define CRYPTO_SERVICES_DEBUG 0

#if CRYPTO_SERVICES_DEBUG
static void crypto_buff_trace(const char * label, const unsigned char* buffer, int len)
{
    printf("\n\t\t label:%s, buffer len:%d, buffer: ", label, len);
    for (int i = 0; i < len; ++i)
      printf("%02x", (unsigned char)(buffer[i]));
}
#define CRYPTO_BUFFER_TRACE(label, buff, len) crypto_buff_trace(label, buff, len)
#else
#define CRYPTO_BUFFER_TRACE(label, buff, len)
#endif

#ifdef CONFIG_OPENSSL
static const EVP_MD *select_hmac(int hmac, size_t *hmac_len)
{       
    const EVP_MD *md = NULL;
    switch (hmac) {
    case NVME_HMAC_ALG_SHA2_256:
            md = EVP_sha256();
            *hmac_len = 32;
            break;
    case NVME_HMAC_ALG_SHA2_384:
            md = EVP_sha384();
            *hmac_len = 48;
            break;  
    default:
            *hmac_len = 0;
            break;
    }               
    return md;
}               
        
static DEFINE_CLEANUP_FUNC(
        cleanup_evp_pkey_ctx, EVP_PKEY_CTX *, EVP_PKEY_CTX_free)
#define _cleanup_evp_pkey_ctx_ __cleanup__(cleanup_evp_pkey_ctx)

int libnvme_hkdf_extract(unsigned char  cipher,
                         const unsigned char  *salt, size_t salt_len,
                         const unsigned char  *ikm,  size_t ikm_len,
                         unsigned char        *prk,  size_t prk_len)
{                      
    CRYPTO_BUFFER_TRACE("ikm", ikm, ikm_len);
    _cleanup_evp_pkey_ctx_ EVP_PKEY_CTX *ctx = NULL;
    const EVP_MD *md;
    size_t hmac_len;
    
    md = select_hmac(cipher, &hmac_len);
    if (!md || !hmac_len) {
            errno = EINVAL;
            return -1;
    }       
            
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!ctx) {
            errno = ENOMEM;
            return -1;
    }       
            
    if (EVP_PKEY_derive_init(ctx) <= 0) {
            errno = ENOMEM;
            return -1;
    }       
            
    if ( EVP_PKEY_CTX_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) <= 0 )
    {
            errno = ENOKEY;
            return -1;
    }       
            
    if (EVP_PKEY_CTX_set_hkdf_md(ctx, md) <= 0) {
            errno = ENOKEY;
            return -1;
    }       
            
    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, ikm, ikm_len) <= 0) {
            errno = ENOKEY;
            return -1;
    }       
            
    if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, salt_len) <= 0) {
            errno = ENOKEY;
            return -1;
    }
    // Generate Key now
    if (EVP_PKEY_derive(ctx, prk, &prk_len) <= 0) {
            errno = ENOKEY;
            return -1;
    }
    CRYPTO_BUFFER_TRACE("prk", prk, prk_len);
    return prk_len;
}



int libnvme_hkdf_expand(unsigned char  cipher,
                       const unsigned char  *prk,  size_t prk_len,
                       const unsigned char  *info, size_t info_len,
                       unsigned char        *okm,  size_t okm_len)
{               
    CRYPTO_BUFFER_TRACE("prk", prk, prk_len);
            
    _cleanup_evp_pkey_ctx_ EVP_PKEY_CTX *ctx = NULL;
            
    const EVP_MD *md;
    size_t hmac_len;
    md = select_hmac(cipher, &hmac_len);
    if (!md || !hmac_len) {
            errno = EINVAL;
            return -1;
    }       
            
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!ctx) { 
            errno = ENOMEM;
            return -1;
    }       
            
    if (EVP_PKEY_derive_init(ctx) <= 0) {
            errno = ENOMEM;
            return -1;
    }
    if ( EVP_PKEY_CTX_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) <= 0 )
    {
            errno = ENOKEY;
            return -1;
    }
    if (EVP_PKEY_CTX_set_hkdf_md(ctx, md) <= 0) {
            errno = ENOKEY;
            return -1;
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, prk, prk_len) <= 0) {
            errno = ENOKEY;
            return -1;
    }
    if (EVP_PKEY_CTX_add1_hkdf_info(ctx, info, info_len) <= 0) {
            errno = ENOKEY;
            return -1;
    }
    // Generate Key now
    if (EVP_PKEY_derive(ctx, okm, &okm_len) <= 0) {
            errno = ENOKEY;
            return -1;
    }
    CRYPTO_BUFFER_TRACE("okm", okm, okm_len);
    return okm_len;
}

#else
int libnvme_hkdf_extract(unsigned char  cipher,
                         const unsigned char  *salt, size_t salt_len,
                         const unsigned char  *ikm,  size_t ikm_len,
                         unsigned char        *prk,  size_t prk_len)
{
    nvme_msg(NULL, LOG_ERR, "NVMe TLS is not supported; "
             "recompile with OpenSSL support.\n");
    errno = ENOTSUP;
    return -1;
}


int libnvme_hkdf_expand(unsigned char  cipher,
                       const unsigned char  *prk,  size_t prk_len,
                       const unsigned char  *info, size_t info_len,
                       unsigned char        *okm,  size_t okm_len)
{
    nvme_msg(NULL, LOG_ERR, "NVMe TLS is not supported; "
             "recompile with OpenSSL support.\n");
    errno = ENOTSUP;
    return -1;
}
#endif

int libnvme_hkdf_expand_label(unsigned char  cipher,
                              const unsigned char  *secret,         size_t   secret_len,
                              const char           *label,          uint8_t  label_len,
                              const unsigned char  *context,        uint8_t  context_len,
                              unsigned char        *derived_secret, uint16_t derived_secret_len)
{
    ////////////////////////////////////////////////////////////////////////////////////////
    // HKDF-Expand-Label(Secret, Label, Context, Length) =
    //            HKDF-Expand(Secret, HkdfLabel, Length)
    //
    //       Where HkdfLabel is specified as:
    //
    //       struct {
    //           uint16 length = Length;
    //           opaque label<7..255> = "tls13 " + Label;
    //           opaque context<0..255> = Context;
    //       } HkdfLabel;
    ////////////////////////////////////////////////////////////////////////////////////////

    uint16_t hkdf_expand_label_len = (((uint16_t)derived_secret_len& 0xFF) << 8) | ((uint16_t)derived_secret_len>> 8);
    // size :  Part 1/3 : Length:2,
    //         Part 2/3 : Labellength:1 + ("tls13 ":6 + label_len)
    //         Part 3/3 : Contextlength:1 + context_len
    _cleanup_free_ unsigned char *hkdf_label_buff = malloc(2+(1+(6+label_len))+(1+context_len));
    if (!hkdf_label_buff) {
        errno = ENOMEM;
        return -1;
    }
    ////////////////////////////////////////////////////////////////////////////////////////
    // HkdfLabel: Part 1/3
    //            uint16 length = Length;
    // The 'Length' needs to be represented based on the network byte-order based on
    // the TLS specification
    ////////////////////////////////////////////////////////////////////////////////////////
    uint16_t hkdf_label_buff_len = 0;
    memcpy(&hkdf_label_buff[hkdf_label_buff_len], (const unsigned char *)&hkdf_expand_label_len, 2);
    hkdf_label_buff_len += 2;
    ////////////////////////////////////////////////////////////////////////////////////////
    // HkdfLabel: Part 2/3
    //            opaque label<7..255> = "tls13 " + Label;
    ////////////////////////////////////////////////////////////////////////////////////////
    const char *tls_13_label = "tls13 ";
    uint8_t f_label_len = strlen(tls_13_label) + label_len;
    memcpy(&hkdf_label_buff[hkdf_label_buff_len], (const unsigned char *)&f_label_len, 1);
    hkdf_label_buff_len += 1;
    memcpy(&hkdf_label_buff[hkdf_label_buff_len], (const unsigned char *)"tls13 ", 6);
    hkdf_label_buff_len += 6;
    memcpy(&hkdf_label_buff[hkdf_label_buff_len], (const unsigned char *)label, label_len);
    hkdf_label_buff_len += label_len;
    ////////////////////////////////////////////////////////////////////////////////////////
    // HkdfLabel: Part 3/3
    //            opaque context<0..255> = Context
    ////////////////////////////////////////////////////////////////////////////////////////
    memcpy(&hkdf_label_buff[hkdf_label_buff_len], (const unsigned char *)&context_len, 1);
    hkdf_label_buff_len += 1;
    memcpy(&hkdf_label_buff[hkdf_label_buff_len], (const unsigned char *)context, context_len);
    hkdf_label_buff_len += context_len;
    return libnvme_hkdf_expand(cipher, secret, secret_len, hkdf_label_buff,
                               hkdf_label_buff_len, derived_secret, derived_secret_len);
}


int libnvme_hkdf_extract_n_expand_label(unsigned char  cipher,
                                        const unsigned char  *secret,         size_t   secret_len,
                                        const char           *label,          uint8_t  label_len,
                                        const unsigned char  *context,        uint8_t  context_len,
                                        unsigned char        *derived_secret, uint16_t derived_secret_len)
{
    _cleanup_free_ unsigned char  *prk;
    size_t prk_len = derived_secret_len;
    prk  = malloc(prk_len);
    if (!prk) {
        errno = ENOMEM;
        return -1;
    }

    int rc = libnvme_hkdf_extract(cipher, NULL, 0, secret, secret_len, prk, prk_len);
    if (rc)
    {
        rc = libnvme_hkdf_expand_label(cipher, prk, prk_len, label, label_len, context, context_len, derived_secret, derived_secret_len);
    }
    return rc;
}


int libnvme_run_HKDF_KAT()
{
    int rc;
    unsigned char cipher = NVME_HMAC_ALG_SHA2_256;

    ///////////////////////////////////////////////////////////////////////////////
    //  HKDF (RFC 5869) test vectors
    //  A.2.  Test Case 2
    //    Test with SHA-256 and longer inputs/outputs
    //    Hash = SHA-256
    //    IKM  = 0x000102030405060708090a0b0c0d0e0f
    //           101112131415161718191a1b1c1d1e1f
    //           202122232425262728292a2b2c2d2e2f
    //           303132333435363738393a3b3c3d3e3f
    //           404142434445464748494a4b4c4d4e4f (80 octets)
    //    salt = 0x606162636465666768696a6b6c6d6e6f
    //           707172737475767778797a7b7c7d7e7f
    //           808182838485868788898a8b8c8d8e8f
    //           909192939495969798999a9b9c9d9e9f
    //           a0a1a2a3a4a5a6a7a8a9aaabacadaeaf (80 octets)
    //    info = 0xb0b1b2b3b4b5b6b7b8b9babbbcbdbebf
    //           c0c1c2c3c4c5c6c7c8c9cacbcccdcecf
    //           d0d1d2d3d4d5d6d7d8d9dadbdcdddedf
    //           e0e1e2e3e4e5e6e7e8e9eaebecedeeef
    //           f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff (80 octets)
    //    L    = 82
    //    PRK  = 0x06a6b88c5853361a06104c9ceb35b45c
    //           ef760014904671014a193f40c15fc244 (32 octets)
    //    OKM  = 0xb11e398dc80327a1c8e7f78c596a4934
    //           4f012eda2d4efad8a050cc4c19afa97c
    //           59045a99cac7827271cb41c65e590e09
    //           da3275600c2f09b8367793a9aca3db71
    //           cc30c58179ec3e87c14c01d5c1f3434f
    //           1d87 (82 octets)
    ///////////////////////////////////////////////////////////////////////////////
    uint8_t _Known_HKDF_IKM[80] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f
    };

    uint8_t _Known_HKDF_SALT[80] =
    {
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    };

    uint8_t _Known_HKDF_INFO[80] =
    {
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
        0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
        0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
        0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
    };

    uint8_t _Known_HKDF_PRK[32] =
    {
        0x06, 0xa6, 0xb8, 0x8c, 0x58, 0x53, 0x36, 0x1a, 0x06, 0x10, 0x4c, 0x9c, 0xeb, 0x35, 0xb4, 0x5c,
        0xef, 0x76, 0x00, 0x14, 0x90, 0x46, 0x71, 0x01, 0x4a, 0x19, 0x3f, 0x40, 0xc1, 0x5f, 0xc2, 0x44,
    };

    uint8_t _Known_HKDF_OKM[82] =
    {
        0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1, 0xc8, 0xe7, 0xf7, 0x8c, 0x59, 0x6a, 0x49, 0x34,
        0x4f, 0x01, 0x2e, 0xda, 0x2d, 0x4e, 0xfa, 0xd8, 0xa0, 0x50, 0xcc, 0x4c, 0x19, 0xaf, 0xa9, 0x7c,
        0x59, 0x04, 0x5a, 0x99, 0xca, 0xc7, 0x82, 0x72, 0x71, 0xcb, 0x41, 0xc6, 0x5e, 0x59, 0x0e, 0x09,
        0xda, 0x32, 0x75, 0x60, 0x0c, 0x2f, 0x09, 0xb8, 0x36, 0x77, 0x93, 0xa9, 0xac, 0xa3, 0xdb, 0x71,
        0xcc, 0x30, 0xc5, 0x81, 0x79, 0xec, 0x3e, 0x87, 0xc1, 0x4c, 0x01, 0xd5, 0xc1, 0xf3, 0x43, 0x4f,
        0x1d, 0x87,
    };


    uint8_t calculated_prk[sizeof(_Known_HKDF_PRK)];
    uint8_t calculated_okm[sizeof(_Known_HKDF_OKM)];
    printf("\n\t Running hkdf_extract() known answer test...");
    rc = libnvme_hkdf_extract(cipher, &_Known_HKDF_SALT[0], sizeof(_Known_HKDF_SALT),
                              &_Known_HKDF_IKM[0], sizeof(_Known_HKDF_IKM), calculated_prk, sizeof(calculated_prk));

    CRYPTO_BUFFER_TRACE("calculated_prk", calculated_prk, sizeof(calculated_prk));
    CRYPTO_BUFFER_TRACE("known______prk", _Known_HKDF_PRK, sizeof(_Known_HKDF_PRK));
    if(rc) {
        if (memcmp(&_Known_HKDF_PRK[0],&calculated_prk[0], sizeof(_Known_HKDF_PRK)) != 0) {
            printf("\n\t hkdf_extract() known answer test...[FAILED]");
            errno = -EINVAL;
            rc = -1;
        }
        else {
            printf("\n\t hkdf_extract() known answer test...[PASSED]");
        }
    }

    if(rc) {
        printf("\n\t Running hkdf_expand() known answer test...");
        rc = libnvme_hkdf_expand(cipher, &calculated_prk[0], sizeof(calculated_prk),
                                 &_Known_HKDF_INFO[0], sizeof(_Known_HKDF_INFO), calculated_okm, sizeof(calculated_okm));

        CRYPTO_BUFFER_TRACE("calculated_okm", calculated_okm, sizeof(calculated_okm));
        CRYPTO_BUFFER_TRACE("known______okm", _Known_HKDF_OKM, sizeof(_Known_HKDF_OKM));
        if(rc) {
            if (memcmp(&_Known_HKDF_PRK[0],&calculated_prk[0], sizeof(_Known_HKDF_PRK)) != 0){
                printf("\n\t hkdf_expand() known answer test...[FAILED]");
                errno = -EINVAL;
                rc = -1;
            }
            else{
                printf("\n\t hkdf_expand() known answer test...[PASSED]");
            }
         }
    }
    return rc;
}


int libnvme_run_HKDF_label_KAT()
{
    int rc;
    unsigned char cipher = NVME_HMAC_ALG_SHA2_256;

    // HKDF::Expand-Label test
    // rfc8448 TLS 1.3 Traces page 5.
    //  {server}  derive secret for handshake "tls13 derived":
    //
    //   PRK (32 octets):  33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c e2
    //      10 ad f3 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a
    //   hash (32 octets):  e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24
    //      27 ae 41 e4 64 9b 93 4c a4 95 99 1b 78 52 b8 55
    //   info (49 octets):  00 20 0d 74 6c 73 31 33 20 64 65 72 69 76 65 64
    //      20 e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24 27 ae 41 e4
    //      64 9b 93 4c a4 95 99 1b 78 52 b8 55
    //   output (32 octets):  6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba b6
    //      97 16 c0 76 18 9c 48 25 0c eb ea c3 57 6c 36 11 ba
    uint8_t _Known_HKDF_EL_PRK[32] =
    {
        0x33, 0xad, 0x0a, 0x1c, 0x60, 0x7e, 0xc0, 0x3b, 0x09, 0xe6, 0xcd, 0x98, 0x93, 0x68, 0x0c, 0xe2,
        0x10, 0xad, 0xf3, 0x00, 0xaa, 0x1f, 0x26, 0x60, 0xe1, 0xb2, 0x2e, 0x10, 0xf1, 0x70, 0xf9, 0x2a
    };

    uint8_t _Known_HKDF_EL_HASH[32] =
    {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };

    uint8_t _Known_HKDF_EL_LABEL[7] =
    {
        'd','e','r','i','v','e','d'
    };

    uint8_t _Known_HKDF_EL_OUTPUT[32] =
    {
        0x6f, 0x26, 0x15, 0xa1, 0x08, 0xc7, 0x02, 0xc5, 0x67, 0x8f, 0x54, 0xfc, 0x9d, 0xba, 0xb6, 0x97,
        0x16, 0xc0, 0x76, 0x18, 0x9c, 0x48, 0x25, 0x0c, 0xeb, 0xea, 0xc3, 0x57, 0x6c, 0x36, 0x11, 0xba
    };

    uint8_t calculated_output[sizeof(_Known_HKDF_EL_OUTPUT)];
    rc = libnvme_run_HKDF_KAT();
    if(rc < 0){
        errno = -EINVAL;
        return -1;
    }

    printf("\n\t Running hkdf_expand_label() known answer test...");
    rc = libnvme_hkdf_expand_label(cipher,
                                   &_Known_HKDF_EL_PRK[0], sizeof(_Known_HKDF_EL_PRK),
                                   (const char *)&_Known_HKDF_EL_LABEL[0], sizeof(_Known_HKDF_EL_LABEL),
                                   &_Known_HKDF_EL_HASH[0],  sizeof(_Known_HKDF_EL_HASH),
                                   &calculated_output[0], sizeof(_Known_HKDF_EL_OUTPUT));

    CRYPTO_BUFFER_TRACE("calculated output", calculated_output, 32);
    CRYPTO_BUFFER_TRACE("     known output", _Known_HKDF_EL_OUTPUT, sizeof(_Known_HKDF_EL_OUTPUT));

    if(rc) {
       if (memcmp(&_Known_HKDF_EL_OUTPUT[0],&calculated_output[0], sizeof(_Known_HKDF_EL_OUTPUT)) != 0) {
           printf("\n\t hkdf_expand_label() known answer test...[FAILED]");
           errno = -EINVAL;
           rc = -1;
       }
       else {
           printf("\n\t hkdf_expand_label() known answer test...[PASSED]");
       }
    }
    return rc;
}
