/*
 * Copyright 2015-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "crypto/evp.h"
#include "crypto/chacha.h"

static EVP_CIPHER chacha20_poly1305 = {
    NID_chacha20_poly1305,
    1,                  /* block_size */
    CHACHA_KEY_SIZE,    /* key_len */
    12,                 /* iv_len, 96-bit nonce in the context */
    EVP_CIPH_FLAG_AEAD_CIPHER | EVP_CIPH_CUSTOM_IV |
    EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT |
    EVP_CIPH_CUSTOM_COPY | EVP_CIPH_FLAG_CUSTOM_CIPHER |
    EVP_CIPH_CUSTOM_IV_LENGTH
};

const EVP_CIPHER *EVP_chacha20_poly1305(void)
{
    return(&chacha20_poly1305);
}

