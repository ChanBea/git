/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * @brief A simple wrapper around the thread calls for the default provider.
 *
 * Algorithms that need to use functions such as ossl_get_avail_threads() and
 * ossl_crypto_thread_start() should use these wrappers if the algorithm needs
 * to be included in the OpenSSL FIPS provider. (e.g. If Argon2 becomes a FIPS
 * algorithm).
 * The FIPS provider has its own copy of the functions listed below since
 * functions such as ossl_get_avail_threads(), and ossl_crypto_thread_start()
 * are not directly available.
 */

#include <openssl/e_os2.h>
#include "prov/providercommon.h"
#include "internal/thread.h"

#if !defined(OPENSSL_NO_DEFAULT_THREAD_POOL)
uint64_t ossl_prov_get_avail_threads(OSSL_LIB_CTX *ctx)
{
    return ossl_get_avail_threads(ctx);
}

void *ossl_prov_thread_start(OSSL_LIB_CTX *ctx, CRYPTO_THREAD_ROUTINE start,
                             void *data)
{
    return ossl_crypto_thread_start(ctx, start, data);
}

int ossl_prov_thread_join(void *task, uint32_t *ret)
{
    return ossl_crypto_thread_join(task, ret);
}

int ossl_prov_thread_clean(void *vhandle)
{
    return ossl_crypto_thread_clean(vhandle);
}
#endif /* OPENSSL_NO_DEFAULT_THREAD_POOL */
