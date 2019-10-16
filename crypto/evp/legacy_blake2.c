/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_BLAKE2

# include <openssl/obj_mac.h>
# include "crypto/evp.h"

static const EVP_MD blake2b_md = {
    NID_blake2b512,
};

const EVP_MD *EVP_blake2b512(void)
{
    return &blake2b_md;
}

static const EVP_MD blake2s_md = {
    NID_blake2s256,
};

const EVP_MD *EVP_blake2s256(void)
{
    return &blake2s_md;
}

#endif /* OPENSSL_NO_BLAKE2 */
