/*
 * Copyright 2001-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* AES-NI section */
static int ccm_aesni_initkey(PROV_CCM_CTX *ctx, const unsigned char *key,
                             size_t keylen)
{
    PROV_AES_CCM_CTX *actx = (PROV_AES_CCM_CTX *)ctx;

    AES_CCM_SET_KEY_FN(aesni_set_encrypt_key, aesni_encrypt,
                       aesni_ccm64_encrypt_blocks, aesni_ccm64_decrypt_blocks);
    return 1;
}

static const PROV_CCM_HW aesni_ccm = {
    ccm_aesni_initkey,
    ccm_generic_setiv,
    ccm_generic_setaad,
    ccm_generic_auth_encrypt,
    ccm_generic_auth_decrypt,
    ccm_generic_gettag
};

const PROV_CCM_HW *PROV_AES_HW_ccm(size_t keybits)
{
    return AESNI_CAPABLE ? &aesni_ccm : &aes_ccm;
}
