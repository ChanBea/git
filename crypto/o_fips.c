/*
 * Copyright 2011-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"

int FIPS_mode(void)
{
    /* This version of the library does not support FIPS mode. */
    return 0;
}

int FIPS_mode_set(int r)
{
    if (r == 0)
        return 1;
    CRYPTOerr(CRYPTO_F_FIPS_MODULE_SET, CRYPTO_R_FIPS_MODULE_NOT_SUPPORTED);
    return 0;
}
