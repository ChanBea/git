/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_OSSL_STOREERR_H
# define OPENSSL_OSSL_STOREERR_H
# pragma once

# include <openssl/opensslconf.h>
# include <openssl/symhacks.h>



/*
 * OSSL_STORE function codes.
 */
# ifndef OPENSSL_NO_DEPRECATED_3_0
#  define OSSL_STORE_F_FILE_ATTACH                         128
#  define OSSL_STORE_F_FILE_CTRL                           129
#  define OSSL_STORE_F_FILE_FIND                           138
#  define OSSL_STORE_F_FILE_GET_PASS                       118
#  define OSSL_STORE_F_FILE_LOAD                           119
#  define OSSL_STORE_F_FILE_LOAD_TRY_DECODE                124
#  define OSSL_STORE_F_FILE_NAME_TO_URI                    126
#  define OSSL_STORE_F_FILE_OPEN                           120
#  define OSSL_STORE_F_OSSL_STORE_ATTACH                   127
#  define OSSL_STORE_F_OSSL_STORE_EXPECT                   130
#  define OSSL_STORE_F_OSSL_STORE_FIND                     131
#  define OSSL_STORE_F_OSSL_STORE_GET0_LOADER_INT          100
#  define OSSL_STORE_F_OSSL_STORE_INFO_GET1_CERT           101
#  define OSSL_STORE_F_OSSL_STORE_INFO_GET1_CRL            102
#  define OSSL_STORE_F_OSSL_STORE_INFO_GET1_NAME           103
#  define OSSL_STORE_F_OSSL_STORE_INFO_GET1_NAME_DESCRIPTION 135
#  define OSSL_STORE_F_OSSL_STORE_INFO_GET1_PARAMS         104
#  define OSSL_STORE_F_OSSL_STORE_INFO_GET1_PKEY           105
#  define OSSL_STORE_F_OSSL_STORE_INFO_NEW_CERT            106
#  define OSSL_STORE_F_OSSL_STORE_INFO_NEW_CRL             107
#  define OSSL_STORE_F_OSSL_STORE_INFO_NEW_EMBEDDED        123
#  define OSSL_STORE_F_OSSL_STORE_INFO_NEW_NAME            109
#  define OSSL_STORE_F_OSSL_STORE_INFO_NEW_PARAMS          110
#  define OSSL_STORE_F_OSSL_STORE_INFO_NEW_PKEY            111
#  define OSSL_STORE_F_OSSL_STORE_INFO_SET0_NAME_DESCRIPTION 134
#  define OSSL_STORE_F_OSSL_STORE_INIT_ONCE                112
#  define OSSL_STORE_F_OSSL_STORE_LOADER_NEW               113
#  define OSSL_STORE_F_OSSL_STORE_OPEN                     114
#  define OSSL_STORE_F_OSSL_STORE_OPEN_INT                 115
#  define OSSL_STORE_F_OSSL_STORE_REGISTER_LOADER_INT      117
#  define OSSL_STORE_F_OSSL_STORE_SEARCH_BY_ALIAS          132
#  define OSSL_STORE_F_OSSL_STORE_SEARCH_BY_ISSUER_SERIAL  133
#  define OSSL_STORE_F_OSSL_STORE_SEARCH_BY_KEY_FINGERPRINT 136
#  define OSSL_STORE_F_OSSL_STORE_SEARCH_BY_NAME           137
#  define OSSL_STORE_F_OSSL_STORE_UNREGISTER_LOADER_INT    116
#  define OSSL_STORE_F_TRY_DECODE_PARAMS                   121
#  define OSSL_STORE_F_TRY_DECODE_PKCS12                   122
#  define OSSL_STORE_F_TRY_DECODE_PKCS8ENCRYPTED           125
# endif

/*
 * OSSL_STORE reason codes.
 */
# define OSSL_STORE_R_AMBIGUOUS_CONTENT_TYPE              107
# define OSSL_STORE_R_BAD_PASSWORD_READ                   115
# define OSSL_STORE_R_ERROR_VERIFYING_PKCS12_MAC          113
# define OSSL_STORE_R_FINGERPRINT_SIZE_DOES_NOT_MATCH_DIGEST 121
# define OSSL_STORE_R_INVALID_SCHEME                      106
# define OSSL_STORE_R_IS_NOT_A                            112
# define OSSL_STORE_R_LOADER_INCOMPLETE                   116
# define OSSL_STORE_R_LOADING_STARTED                     117
# define OSSL_STORE_R_NOT_A_CERTIFICATE                   100
# define OSSL_STORE_R_NOT_A_CRL                           101
# define OSSL_STORE_R_NOT_A_NAME                          103
# define OSSL_STORE_R_NOT_A_PRIVATE_KEY                   102
# define OSSL_STORE_R_NOT_A_PUBLIC_KEY                    122
# define OSSL_STORE_R_NOT_PARAMETERS                      104
# define OSSL_STORE_R_PASSPHRASE_CALLBACK_ERROR           114
# define OSSL_STORE_R_PATH_MUST_BE_ABSOLUTE               108
# define OSSL_STORE_R_SEARCH_ONLY_SUPPORTED_FOR_DIRECTORIES 119
# define OSSL_STORE_R_UI_PROCESS_INTERRUPTED_OR_CANCELLED 109
# define OSSL_STORE_R_UNREGISTERED_SCHEME                 105
# define OSSL_STORE_R_UNSUPPORTED_CONTENT_TYPE            110
# define OSSL_STORE_R_UNSUPPORTED_OPERATION               118
# define OSSL_STORE_R_UNSUPPORTED_SEARCH_TYPE             120
# define OSSL_STORE_R_URI_AUTHORITY_UNSUPPORTED           111

#endif
