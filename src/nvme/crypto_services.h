// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2025 Western Digital Corporation or its affiliates.
 *
 * Authors: Chiranjeb Mondal <chiranjeb.mondal@wdc.com>
 *
 */

#ifndef _LIBNVME_CRYPTO_SERVICES_H
#define _LIBNVME_CRYPTO_SERVICES_H

#include "types.h"

/**
 * libnvme_hkdf_extract() - HKDF-Extract(salt, IKM)
 * 
 * @cipher:	hmac algorithm
 * @salt:	'salt' to be used in HKDF-Extract(salt, IKM)
 * @salt_len: length of the salt
 * @ikm:	'IKM' to be used in HKDF-Extract(salt, IKM)
 * @ikm_len: length of the ikm
 * @prk:	output of HKDF-Extract(salt, IKM)
 * @prk_len: length of the prk
 * 
 * This function implements HKDF-Extract(salt, IKM) -> PRK 
 * defined in https://datatracker.ietf.org/doc/html/rfc5869
 * 
 * Return: The functon returns positive number on success,
 *         a negative number with errno set otherwise.
 */
int libnvme_hkdf_extract(unsigned char  cipher,
                         const unsigned char  *salt, size_t salt_len,
                         const unsigned char  *ikm,  size_t ikm_len,
                         unsigned char        *prk,  size_t prk_len);

/**
 * libnvme_hkdf_expand() - HKDF-Expand
 * 
 * @cipher:	hmac algorithm
 * @prk:	'PRK' to be used in HKDF-Expand(PRK, info, L)
 * @prk_len: length of the prk
 * @info: 'info' to be used in HKDF-Expand(PRK, info, L)
 * @info_len: length of the label in bytes
 * @okm: output of HKDF-Expand(PRK, info, L)
 * @okm_len: length of the okm
 * 
 * This function implements HKDF-Expand(PRK, info, L) -> OKM 
 * defined in https://datatracker.ietf.org/doc/html/rfc5869
 * 
 * Return: The functon returns positive number on success,
 *         a negative number with errno set otherwise.
 */
int libnvme_hkdf_expand(unsigned char  cipher,
                       const unsigned char  *prk,  size_t prk_len,
                       const unsigned char  *info, size_t info_len,
                       unsigned char        *okm,  size_t okm_len);

/**
 * libnvme_hkdf_expand_label() - HKDF-Expand-Label
 * 
 * @cipher:	hmac algorithm
 * @secret:	'Secret' to be used in HKDF-Expand-Label(Secret, Label, Context, Length)
 * @secret_len: length of the secret
 * @label: 'Label' to be used in HKDF-Expand-Label(Secret, Label, Context, Length)
 * @label_len: length of the label in bytes
 * @context: 'Context' to be used in HKDF-Expand-Label(Secret, Label, Context, Length)
 * @context_len: length of the context in bytes
 * @derived_secret:	output of HKDF-Expand-Label(Secret, Label, Context, Length)
 * @derived_secret_len: length of derived_secret in bytes
 * 
 * This function implements HKDF-Expand-Label(Secret, Label, Context, Length) 
 * defined in https://datatracker.ietf.org/doc/html/rfc8446#page-102
 * 
 * Return: The functon returns positive number on success,
 *         a negative number with errno set otherwise.
 */
int libnvme_hkdf_expand_label(unsigned char  cipher,
                              const unsigned char  *secret,         size_t   secret_len,
                              const char           *label,          uint8_t  label_len,
                              const unsigned char  *context,        uint8_t  context_len,
                              unsigned char        *derived_secret, uint16_t derived_secret_len);

/**
 * libnvme_hkdf_extract_n_expand_label() - wrapper for  HKDF-Extract and HKDF-Expand-Label
 * 
 * @cipher:	hmac algorithm
 * @secret:	'Secret' to be used in HKDF-Expand-Label(Secret, Label, Context, Length)
 * @label: 'Label' to be used in HKDF-Expand-Label(Secret, Label, Context, Length)
 * @label_len: length of the label in bytes
 * @context: 'Context' to be used in HKDF-Expand-Label(Secret, Label, Context, Length)
 * @context_len: length of the context in bytes
 * @derived_secret:	output of HKDF-Expand-Label(Secret, Label, Context, Length)
 * @derived_secret_len: length of derived_secret in bytes
 * 
 * This function wraps the implementation of the following two hkdf functions:
 *    HKDF-Extract(salt, IKM) -> PRK (defined in https://datatracker.ietf.org/doc/html/rfc5869), followed by 
 *    HKDF-Expand-Label(Secret, Label, Context, Length) (https://datatracker.ietf.org/doc/html/rfc8446#page-102)
 * 
 * Return: The functon returns positive number on success,
 *         a negative number with errno set otherwise.
 */
int libnvme_hkdf_extract_n_expand_label(unsigned char  cipher,
                                        const unsigned char  *secret,         size_t   secret_len,
                                        const char           *label,          uint8_t  label_len,
                                        const unsigned char  *context,        uint8_t  context_len,
                                        unsigned char        *derived_secret, uint16_t derived_secret_len);

/**
 * libnvme_run_HKDF_label_KAT() -  algorithm verification for HKDF-Extract and HKDF-Expand
 * 
 * Return: The functon returns positive number on success,
 *         a negative number with errno set otherwise.
 */
int libnvme_run_HKDF_KAT();

/**
 * libnvme_run_HKDF_label_KAT() -  algorithm verification for all HKDF functions
 * 
 * This function runs known-answer test for HKDF-Extract, HKDF-Expand, and HKDF-Expand-Label
 * 
 * Return: The functon returns positive number on success,
 *         a negative number with errno set otherwise.
 */
int libnvme_run_HKDF_label_KAT();

#endif
