/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_E_CAPI_ERR_H
# define OSSL_E_CAPI_ERR_H
# pragma once

# include <openssl/opensslconf.h>
# include <openssl/symhacks.h>


# define CAPIerr(f, r) ERR_CAPI_error(0, (r), OPENSSL_FILE, OPENSSL_LINE)


/*
 * CAPI function codes.
 */
# ifndef OPENSSL_NO_DEPRECATED_3_0
#  define CAPI_F_CAPI_CERT_GET_FNAME                       99
#  define CAPI_F_CAPI_CTRL                                 100
#  define CAPI_F_CAPI_CTX_NEW                              101
#  define CAPI_F_CAPI_CTX_SET_PROVNAME                     102
#  define CAPI_F_CAPI_DSA_DO_SIGN                          114
#  define CAPI_F_CAPI_GET_KEY                              103
#  define CAPI_F_CAPI_GET_PKEY                             115
#  define CAPI_F_CAPI_GET_PROVNAME                         104
#  define CAPI_F_CAPI_GET_PROV_INFO                        105
#  define CAPI_F_CAPI_INIT                                 106
#  define CAPI_F_CAPI_LIST_CONTAINERS                      107
#  define CAPI_F_CAPI_LOAD_PRIVKEY                         108
#  define CAPI_F_CAPI_OPEN_STORE                           109
#  define CAPI_F_CAPI_RSA_PRIV_DEC                         110
#  define CAPI_F_CAPI_RSA_PRIV_ENC                         111
#  define CAPI_F_CAPI_RSA_SIGN                             112
#  define CAPI_F_CAPI_VTRACE                               118
#  define CAPI_F_CERT_SELECT_DIALOG                        117
#  define CAPI_F_CLIENT_CERT_SELECT                        116
#  define CAPI_F_WIDE_TO_ASC                               113
# endif

/*
 * CAPI reason codes.
 */
# define CAPI_R_CANT_CREATE_HASH_OBJECT                   100
# define CAPI_R_CANT_FIND_CAPI_CONTEXT                    101
# define CAPI_R_CANT_GET_KEY                              102
# define CAPI_R_CANT_SET_HASH_VALUE                       103
# define CAPI_R_CRYPTACQUIRECONTEXT_ERROR                 104
# define CAPI_R_CRYPTENUMPROVIDERS_ERROR                  105
# define CAPI_R_DECRYPT_ERROR                             106
# define CAPI_R_ENGINE_NOT_INITIALIZED                    107
# define CAPI_R_ENUMCONTAINERS_ERROR                      108
# define CAPI_R_ERROR_ADDING_CERT                         109
# define CAPI_R_ERROR_CREATING_STORE                      110
# define CAPI_R_ERROR_GETTING_FRIENDLY_NAME               111
# define CAPI_R_ERROR_GETTING_KEY_PROVIDER_INFO           112
# define CAPI_R_ERROR_OPENING_STORE                       113
# define CAPI_R_ERROR_SIGNING_HASH                        114
# define CAPI_R_FILE_OPEN_ERROR                           115
# define CAPI_R_FUNCTION_NOT_SUPPORTED                    116
# define CAPI_R_GETUSERKEY_ERROR                          117
# define CAPI_R_INVALID_DIGEST_LENGTH                     118
# define CAPI_R_INVALID_DSA_PUBLIC_KEY_BLOB_MAGIC_NUMBER  119
# define CAPI_R_INVALID_LOOKUP_METHOD                     120
# define CAPI_R_INVALID_PUBLIC_KEY_BLOB                   121
# define CAPI_R_INVALID_RSA_PUBLIC_KEY_BLOB_MAGIC_NUMBER  122
# define CAPI_R_PUBKEY_EXPORT_ERROR                       123
# define CAPI_R_PUBKEY_EXPORT_LENGTH_ERROR                124
# define CAPI_R_UNKNOWN_COMMAND                           125
# define CAPI_R_UNSUPPORTED_ALGORITHM_NID                 126
# define CAPI_R_UNSUPPORTED_PADDING                       127
# define CAPI_R_UNSUPPORTED_PUBLIC_KEY_ALGORITHM          128
# define CAPI_R_WIN32_ERROR                               129

#endif
