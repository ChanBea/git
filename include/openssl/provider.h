/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_PROVIDER_H
# define OSSL_PROVIDER_H

# include <openssl/core.h>

# ifdef __cplusplus
extern "C" {
# endif

/* Load and unload a provider */
OSSL_PROVIDER *OSSL_PROVIDER_load(OPENSSL_CTX *, const char *name);
int OSSL_PROVIDER_unload(OSSL_PROVIDER *prov);

const OSSL_PARAM *OSSL_PROVIDER_get_param_types(const OSSL_PROVIDER *prov);
int OSSL_PROVIDER_get_params(const OSSL_PROVIDER *prov, OSSL_PARAM params[]);

/* Add a built in providers */
int OSSL_PROVIDER_add_builtin(OPENSSL_CTX *, const char *name,
                              OSSL_provider_init_fn *init_fn);

# ifdef __cplusplus
}
# endif

#endif
