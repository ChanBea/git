/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_E_AFALG_ERR_H
# define OSSL_E_AFALG_ERR_H
# pragma once

# include <openssl/opensslconf.h>
# include <openssl/symhacks.h>


# define AFALGerr(f, r) ERR_AFALG_error(0, (r), OPENSSL_FILE, OPENSSL_LINE)


/*
 * AFALG reason codes.
 */
# define AFALG_R_EVENTFD_FAILED                           108
# define AFALG_R_FAILED_TO_GET_PLATFORM_INFO              111
# define AFALG_R_INIT_FAILED                              100
# define AFALG_R_IO_SETUP_FAILED                          105
# define AFALG_R_KERNEL_DOES_NOT_SUPPORT_AFALG            101
# define AFALG_R_KERNEL_DOES_NOT_SUPPORT_ASYNC_AFALG      107
# define AFALG_R_MEM_ALLOC_FAILED                         102
# define AFALG_R_SOCKET_ACCEPT_FAILED                     110
# define AFALG_R_SOCKET_BIND_FAILED                       103
# define AFALG_R_SOCKET_CREATE_FAILED                     109
# define AFALG_R_SOCKET_OPERATION_FAILED                  104
# define AFALG_R_SOCKET_SET_KEY_FAILED                    106

#endif
