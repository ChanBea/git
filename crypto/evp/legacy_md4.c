/*
 * Copyright 2015-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_MD4

# include <openssl/md4.h>
# include "crypto/evp.h"

static const EVP_MD md4_md = {
    NID_md4,
    NID_md4WithRSAEncryption,
    MD4_DIGEST_LENGTH,
    0,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    MD4_CBLOCK,
};

const EVP_MD *EVP_md4(void)
{
    return &md4_md;
}

#endif /* OPENSSL_NO_MD4 */
