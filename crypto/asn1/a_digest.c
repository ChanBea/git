/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* We need to use some engine deprecated APIs */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <stdio.h>
#include <time.h>
#include <sys/types.h>

#include "internal/cryptlib.h"

#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/x509.h>
#include "crypto/x509.h"

#ifndef OPENSSL_NO_DEPRECATED_3_0

int ASN1_digest(i2d_of_void *i2d, const EVP_MD *type, char *data,
                unsigned char *md, unsigned int *len)
{
    int inl;
    unsigned char *str, *p;

    inl = i2d(data, NULL);
    if (inl <= 0) {
        ASN1err(ASN1_F_ASN1_DIGEST, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if ((str = OPENSSL_malloc(inl)) == NULL) {
        ASN1err(ASN1_F_ASN1_DIGEST, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    p = str;
    i2d(data, &p);

    if (!EVP_Digest(str, inl, md, len, type, NULL)) {
        OPENSSL_free(str);
        return 0;
    }
    OPENSSL_free(str);
    return 1;
}

#endif

int asn1_item_digest_with_libctx(const ASN1_ITEM *it, const EVP_MD *md,
                                 void *asn, unsigned char *data,
                                 unsigned int *len, OPENSSL_CTX *libctx,
                                 const char *propq)
{
    int i, ret = 0;
    unsigned char *str = NULL;
    EVP_MD *fetched_md = (EVP_MD *)md;

    i = ASN1_item_i2d(asn, &str, it);
    if (str == NULL)
        return 0;

    if (EVP_MD_provider(md) == NULL) {
#if !defined(OPENSSL_NO_ENGINE)
        if (ENGINE_get_digest_engine(EVP_MD_type(md)) == NULL)
#endif
            fetched_md = EVP_MD_fetch(libctx, EVP_MD_name(md), propq);
    }
     if (fetched_md == NULL)
         goto err;

    ret = EVP_Digest(str, i, data, len, fetched_md, NULL);
err:
    OPENSSL_free(str);
    if (fetched_md != md)
        EVP_MD_free(fetched_md);
    return ret;
}

int ASN1_item_digest(const ASN1_ITEM *it, const EVP_MD *md, void *asn,
                     unsigned char *data, unsigned int *len)
{
    return asn1_item_digest_with_libctx(it, md, asn, data, len, NULL, NULL);
}

