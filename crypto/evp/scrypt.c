/* scrypt.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2015.
 */
/* ====================================================================
 * Copyright (c) 2015 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <internal/numbers.h>

#ifndef OPENSSL_NO_SCRYPT

#define R(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
static void salsa208_word_specification(uint32_t inout[16])
{
    int i;
    uint32_t x[16];
    memcpy(x, inout, sizeof(x));
    for (i = 8; i > 0; i -= 2) {
        x[4] ^= R(x[0] + x[12], 7);
        x[8] ^= R(x[4] + x[0], 9);
        x[12] ^= R(x[8] + x[4], 13);
        x[0] ^= R(x[12] + x[8], 18);
        x[9] ^= R(x[5] + x[1], 7);
        x[13] ^= R(x[9] + x[5], 9);
        x[1] ^= R(x[13] + x[9], 13);
        x[5] ^= R(x[1] + x[13], 18);
        x[14] ^= R(x[10] + x[6], 7);
        x[2] ^= R(x[14] + x[10], 9);
        x[6] ^= R(x[2] + x[14], 13);
        x[10] ^= R(x[6] + x[2], 18);
        x[3] ^= R(x[15] + x[11], 7);
        x[7] ^= R(x[3] + x[15], 9);
        x[11] ^= R(x[7] + x[3], 13);
        x[15] ^= R(x[11] + x[7], 18);
        x[1] ^= R(x[0] + x[3], 7);
        x[2] ^= R(x[1] + x[0], 9);
        x[3] ^= R(x[2] + x[1], 13);
        x[0] ^= R(x[3] + x[2], 18);
        x[6] ^= R(x[5] + x[4], 7);
        x[7] ^= R(x[6] + x[5], 9);
        x[4] ^= R(x[7] + x[6], 13);
        x[5] ^= R(x[4] + x[7], 18);
        x[11] ^= R(x[10] + x[9], 7);
        x[8] ^= R(x[11] + x[10], 9);
        x[9] ^= R(x[8] + x[11], 13);
        x[10] ^= R(x[9] + x[8], 18);
        x[12] ^= R(x[15] + x[14], 7);
        x[13] ^= R(x[12] + x[15], 9);
        x[14] ^= R(x[13] + x[12], 13);
        x[15] ^= R(x[14] + x[13], 18);
    }
    for (i = 0; i < 16; ++i)
        inout[i] += x[i];
    OPENSSL_cleanse(x, sizeof(x));
}

static void scryptBlockMix(uint32_t *B_, uint32_t *B, uint64_t r)
{
    uint64_t i, j;
    uint32_t X[16], *pB;

    memcpy(X, B + (r * 2 - 1) * 16, sizeof(X));
    pB = B;
    for (i = 0; i < r * 2; i++) {
        for (j = 0; j < 16; j++)
            X[j] ^= *pB++;
        salsa208_word_specification(X);
        memcpy(B_ + (i / 2 + (i & 1) * r) * 16, X, sizeof(X));
    }
    OPENSSL_cleanse(X, sizeof(X));
}

static void scryptROMix(unsigned char *B, uint64_t r, uint64_t N,
                        uint32_t *X, uint32_t *T, uint32_t *V)
{
    unsigned char *pB;
    uint32_t *pV;
    uint64_t i, k;

    /* Convert from little endian input */
    for (pV = V, i = 0, pB = B; i < 32 * r; i++, pV++) {
        *pV = *pB++;
        *pV |= *pB++ << 8;
        *pV |= *pB++ << 16;
        *pV |= (uint32_t)*pB++ << 24;
    }

    for (i = 1; i < N; i++, pV += 32 * r)
        scryptBlockMix(pV, pV - 32 * r, r);

    scryptBlockMix(X, V + (N - 1) * 32 * r, r);

    for (i = 0; i < N; i++) {
        uint32_t j;
        j = X[16 * (2 * r - 1)] % N;
        pV = V + 32 * r * j;
        for (k = 0; k < 32 * r; k++)
            T[k] = X[k] ^ *pV++;
        scryptBlockMix(X, T, r);
    }
    /* Convert output to little endian */
    for (i = 0, pB = B; i < 32 * r; i++) {
        uint32_t xtmp = X[i];
        *pB++ = xtmp & 0xff;
        *pB++ = (xtmp >> 8) & 0xff;
        *pB++ = (xtmp >> 16) & 0xff;
        *pB++ = (xtmp >> 24) & 0xff;
    }
}

#ifndef SIZE_MAX
# define SIZE_MAX    ((size_t)-1)
#endif

/*
 * Maximum power of two that will fit in uint64_t: this should work on
 * most (all?) platforms.
 */

#define LOG2_UINT64_MAX         (sizeof(uint64_t) * 8 - 1)

/*
 * Maximum value of p * r:
 * p <= ((2^32-1) * hLen) / MFLen =>
 * p <= ((2^32-1) * 32) / (128 * r) =>
 * p * r <= (2^30-1)
 *
 */

#define SCRYPT_PR_MAX   ((1 << 30) - 1)

/*
 * Maximum permitted memory allow this to be overridden with Configuration
 * option: e.g. -DSCRYPT_MAX_MEM=0 for maximum possible.
 */

#ifdef SCRYPT_MAX_MEM
# if SCRYPT_MAX_MEM == 0
#  undef SCRYPT_MAX_MEM
/*
 * Although we could theoretically allocate SIZE_MAX memory that would leave
 * no memory available for anything else so set limit as half that.
 */
#  define SCRYPT_MAX_MEM (SIZE_MAX/2)
# endif
#else
/* Default memory limit: 32 MB */
# define SCRYPT_MAX_MEM  (1024 * 1024 * 32)
#endif

int EVP_PBE_scrypt(const char *pass, size_t passlen,
                   const unsigned char *salt, size_t saltlen,
                   uint64_t N, uint64_t r, uint64_t p, uint64_t maxmem,
                   unsigned char *key, size_t keylen)
{
    int rv = 0;
    unsigned char *B;
    uint32_t *X, *V, *T;
    uint64_t i, Blen, Vlen;

    /* Sanity check parameters */
    /* initial check, r,p must be non zero, N >= 2 and a power of 2 */
    if (r == 0 || p == 0 || N < 2 || (N & (N - 1)))
        return 0;
    /* Check p * r < SCRYPT_PR_MAX avoiding overflow */
    if (p > SCRYPT_PR_MAX / r)
        return 0;

    /*
     * Need to check N: if 2^(128 * r / 8) overflows limit this is
     * automatically satisfied since N <= UINT64_MAX.
     */

    if (16 * r <= LOG2_UINT64_MAX) {
        if (N >= (1UL << (16 * r)))
            return 0;
    }

    /* Memory checks: check total allocated buffer size fits in uint64_t */

    /*
     * B size in section 5 step 1.S
     * Note: we know p * 128 * r < UINT64_MAX because we already checked
     * p * r < SCRYPT_PR_MAX
     */
    Blen = p * 128 * r;

    /*
     * Check 32 * r * (N + 2) * sizeof(uint32_t) fits in uint64_t.
     * This is combined size V, X and T (section 4)
     */
    i = UINT64_MAX / (32 * sizeof(uint32_t));
    if (N + 2 > i / r)
        return 0;
    Vlen = 32 * r * (N + 2) * sizeof(uint32_t);

    /* check total allocated size fits in uint64_t */
    if (Blen > UINT64_MAX - Vlen)
        return 0;

    if (maxmem == 0)
        maxmem = SCRYPT_MAX_MEM;

    if (Blen + Vlen > maxmem) {
        EVPerr(EVP_F_EVP_PBE_SCRYPT, EVP_R_MEMORY_LIMIT_EXCEEDED);
        return 0;
    }

    /* If no key return to indicate parameters are OK */
    if (key == NULL)
        return 1;

    B = OPENSSL_malloc(Blen + Vlen);
    if (B == NULL)
        return 0;
    X = (uint32_t *)(B + Blen);
    T = X + 32 * r;
    V = T + 32 * r;
    if (PKCS5_PBKDF2_HMAC(pass, passlen, salt, saltlen, 1, EVP_sha256(),
                          Blen, B) == 0)
        goto err;

    for (i = 0; i < p; i++)
        scryptROMix(B + 128 * r * i, r, N, X, T, V);

    if (PKCS5_PBKDF2_HMAC(pass, passlen, B, Blen, 1, EVP_sha256(),
                          keylen, key) == 0)
        goto err;
    rv = 1;
#ifdef SCRYPT_DEBUG
    fprintf(stderr, "scrypt parameters:\n");
    fprintf(stderr, "N=%lu, p=%lu, r=%lu\n", N, p, r);
    fprintf(stderr, "Salt:\n");
    BIO_dump_fp(stderr, (char *)salt, saltlen);
    fprintf(stderr, "Password:\n");
    BIO_dump_fp(stderr, (char *)pass, passlen);
    fprintf(stderr, "Key:\n");
    BIO_dump_fp(stderr, (char *)key, keylen);
#endif
 err:
    OPENSSL_clear_free(B, Blen + Vlen);
    return rv;
}
#endif
