/*
 * Copyright 2001-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Fujitsu SPARC64 X support for AES CCM */

static int ccm_t4_aes_initkey(PROV_CCM_CTX *ctx, const unsigned char *key,
                              size_t keylen)
{
    PROV_AES_CCM_CTX *actx = (PROV_AES_CCM_CTX *)ctx;

    AES_CCM_SET_KEY_FN(aes_t4_set_encrypt_key, aes_t4_encrypt, NULL, NULL);
    return 1;
}

static const PROV_CCM_HW t4_aes_ccm = {
    ccm_t4_aes_initkey,
    ccm_generic_setiv,
    ccm_generic_setaad,
    ccm_generic_auth_encrypt,
    ccm_generic_auth_decrypt,
    ccm_generic_gettag
};

const PROV_CCM_HW *PROV_AES_HW_ccm(size_t keybits)
{
    return SPARC_AES_CAPABLE ? &t4_aes_ccm : &aes_ccm;
}
