/* crypto/bn/bn_prime.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright (c) 1998-2001 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
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

#include <stdio.h>
#include <time.h>
#include "cryptlib.h"
#include "bn_lcl.h"
#include <openssl/rand.h>

/* NB: these functions have been "upgraded", the deprecated versions (which are
 * compatibility wrappers using these functions) are in bn_depr.c.
 * - Geoff
 */

/* The quick sieve algorithm approach to weeding out primes is
 * Philip Zimmermann's, as implemented in PGP.  I have had a read of
 * his comments and implemented my own version.
 */
#include "bn_prime.h"

static int probable_prime(BIGNUM *rnd, int bits);
static int probable_prime_single_word(BIGNUM *rnd, int bits);
static int probable_prime_dh_coprime(BIGNUM *rnd, const int bits,
	const BIGNUM *add, const BIGNUM *rem, BN_CTX *ctx,
	uint prm_offsets[PRIME_OFFSET_COUNT], uint prm_offset_count,
	const uint prm_multiplier, const int prm_multiplier_bits,
	const uint max_rem, const int biased);
static int adjust_rnd_for_dh(BIGNUM *rnd, const BIGNUM *add, const BIGNUM *rem,
	BIGNUM *temp_bn, BN_CTX *ctx);
static int coprime_trial_division(BIGNUM *rnd, const uint max_rem);
static int coprime_trial_division_biased(BIGNUM *rnd, const int bits,
	uint prm_offsets[PRIME_OFFSET_COUNT], uint prm_offset_count,
	const uint prm_multiplier, const uint max_rem,
	const uint initial_offset_index, const BN_ULONG initial_offset);
static int witness(BIGNUM *w, const BIGNUM *a, const BIGNUM *a1,
	const BIGNUM *a1_odd, int k, BN_CTX *ctx, BN_MONT_CTX *mont);

int BN_GENCB_call(BN_GENCB *cb, int a, int b)
	{
	/* No callback means continue */
	if (!cb) return 1;

	switch (cb -> ver)
		{
		case 1:
			{
			/* Deprecated-style callbacks */
			if (cb -> cb.cb_1)
				{
				cb -> cb.cb_1(a, b, cb -> arg);
				}
			return 1;
			}
		case 2:
			{
			/* New-style callbacks */
			return cb -> cb.cb_2(a, b, cb);
			}
		default:
			{
			break;
			}
		}

	/* Unrecognised callback type */
	return 0;
	}

int BN_generate_prime_ex(BIGNUM *ret, int bits, int safe,
	const BIGNUM *add, const BIGNUM *rem, BN_GENCB *cb)
	{
	BN_CTX *ctx;
	BIGNUM *t;
	int i;
	int j;
	int c1 = 0;
	int checks = BN_prime_checks_for_size(bits);
	int found = 0;

	if (bits < 2 || (bits == 2 && safe))
		{
		/* There are no prime numbers with less than two bits and the
		 * smallest safe prime (7) is three bits. */
		BNerr(BN_F_BN_GENERATE_PRIME_EX, BN_R_BITS_TOO_SMALL);
		goto err;
		}

	if ((ctx = BN_CTX_new()) == NULL) goto err;
	BN_CTX_start(ctx);

	if (!(t = BN_CTX_get(ctx))) goto err;

loop: 
	/* make a random number and set the top and bottom bits */
	if (add == NULL)
		{
		if (!bn_probable_prime(ret, bits)) goto err;
		}
	else
		{
		/* always do safe since it's faster than unsafe */
		if (!bn_probable_prime_dh_coprime(ret, bits, add, rem, ctx, 1, 1)) goto err;
		}

	if (!BN_GENCB_call(cb, 0, c1++)) goto err;

	if (safe)
		{
		/* for "safe prime" generation,
		 * check that (p-1)/2 is prime.
		 * Since a prime is odd, We just
		 * need to divide by 2 */
		if (!BN_rshift1(t, ret)) goto err;

		for (i=0; i < checks; i++)
			{
			j = BN_is_prime_fasttest_ex(ret, 1, ctx, 0, cb);
			if (j == -1) goto err;
			if (j == 0) goto loop;

			j = BN_is_prime_fasttest_ex(t, 1, ctx, 0, cb);
			if (j == -1) goto err;
			if (j == 0) goto loop;

			if (!BN_GENCB_call(cb, 2, c1 - 1)) goto err;
			/* We have a safe prime test pass */
			}
		}
	else
		{
		i = BN_is_prime_fasttest_ex(ret, checks, ctx, 0, cb);
		if (i == -1) goto err;
		if (i == 0) goto loop;
		}

	/* we have a prime :-) */
	found = 1;

err:
	if (ctx != NULL)
		{
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
		}

	bn_check_top(ret);

	return found;
	}

int BN_is_prime_ex(const BIGNUM *a, int checks, BN_CTX *ctx_passed, BN_GENCB *cb)
	{
	return BN_is_prime_fasttest_ex(a, checks, ctx_passed, 0, cb);
	}

int BN_is_prime_fasttest_ex(const BIGNUM *a, int checks, BN_CTX *ctx_passed,
		int do_trial_division, BN_GENCB *cb)
	{
	int i;
	int j;
	int k;
	BIGNUM *A1;
	BIGNUM *A1_odd;
	BIGNUM *check; /* taken from ctx */
	BN_CTX *ctx = NULL;
	BN_MONT_CTX *mont = NULL;
	const BIGNUM *A = NULL;
	int ret = -1;

	if (BN_cmp(a, BN_value_one()) <= 0)
		{
		ret = 0;
		goto end;
		}
	
	if (checks == BN_prime_checks)
		{
		checks = BN_prime_checks_for_size(BN_num_bits(a));
		}

	/* first look for small factors */
	if (!BN_is_odd(a))
		{
		/* a is even => a is prime if and only if a == 2 */
		ret = BN_is_word(a, 2);
		goto end;
		}

	if (do_trial_division)
		{
		for (i = 1; i < NUMPRIMES; i++)
			{
			if (BN_mod_word(a, primes[i]) == 0)
				{
				ret = 0;
				goto end;
				}
			}

		if (!BN_GENCB_call(cb, 1, -1)) goto end;
		}

	if (ctx_passed != NULL)
		{
		ctx = ctx_passed;
		}
	else
		{
		if ((ctx = BN_CTX_new()) == NULL) goto end;
		}

	BN_CTX_start(ctx);

	/* A := abs(a) */
	if (a -> neg)
		{
		BIGNUM *t;
		if ((t = BN_CTX_get(ctx)) == NULL) goto end;
		BN_copy(t, a);
		t -> neg = 0;

		A = t;
		}
	else
		{
		A = a;
		}

	if ((A1 = BN_CTX_get(ctx)) == NULL) goto end;
	if ((A1_odd = BN_CTX_get(ctx)) == NULL) goto end;
	if ((check = BN_CTX_get(ctx)) == NULL) goto end;

	/* compute A1 := A - 1 */
	if (!BN_copy(A1, A)) goto end;
	if (!BN_sub_word(A1, 1)) goto end;
	if (BN_is_zero(A1))
		{
		ret = 0;
		goto end;
		}

	/* write  A1  as  A1_odd * 2^k */
	k = 1;
	while (!BN_is_bit_set(A1, k))
		{
		k++;
		}

	if (!BN_rshift(A1_odd, A1, k)) goto end;

	/* Montgomery setup for computations mod A */
	if ((mont = BN_MONT_CTX_new()) == NULL) goto end;
	if (!BN_MONT_CTX_set(mont, A, ctx)) goto end;
	
	for (i = 0; i < checks; i++)
		{
		if (!BN_pseudo_rand_range(check, A1)) goto end;
		if (!BN_add_word(check, 1)) goto end;

		/* now 1 <= check < A */

		j = witness(check, A, A1, A1_odd, k, ctx, mont);
		if (j == -1) goto end;
		if (j)
			{
			ret = 0;
			goto end;
			}

		if(!BN_GENCB_call(cb, 1, i)) goto end;
		}

	ret = 1;

end:
	if (ctx != NULL)
		{
		BN_CTX_end(ctx);
		if (ctx_passed == NULL)
			{
			BN_CTX_free(ctx);
			}
		}

	if (mont != NULL)
		{
		BN_MONT_CTX_free(mont);
		}

	return ret;
	}

int bn_probable_prime(BIGNUM *rnd, int bits)
	{	
	int ret = 0;

	if (bits > BN_BITS2)
		{
		if (!probable_prime(rnd, bits)) goto err;
		}
	else
		{
		if (!probable_prime_single_word(rnd, bits)) goto err;
		}

	ret = 1;

err:
	bn_check_top(rnd);
	return ret;
	}

static int probable_prime(BIGNUM *rnd, int bits)
	{	
	int i;
	prime_t mods[NUMPRIMES];
	BN_ULONG delta;
	BN_ULONG maxdelta = BN_MASK2 - primes[NUMPRIMES - 1] + 1;
	int ret = 0;
	
again:
	if (!BN_rand(rnd, bits, 1, 1)) goto err;
		
	for (i=1; i < NUMPRIMES; i++)
		{
		mods[i] = (prime_t)BN_mod_word(rnd, (BN_ULONG)primes[i]);
		}

	delta = 0;

loop:
	for (i=1; i < NUMPRIMES; i++)
		{
		/* check that rnd is not a prime and also
		 * that gcd(rnd-1,primes) == 1 (except for 2) */
		if (((mods[i] + delta) % primes[i]) <= 1)
			{
			delta += 2;
			if (delta > maxdelta) goto again;
			goto loop;
			}
		}

	if (!BN_add_word(rnd, delta)) goto err;
	if (BN_num_bits(rnd) != bits) goto again;
	
	ret = 1;
	
err:
	bn_check_top(rnd);
	return ret;
	}

static int probable_prime_single_word(BIGNUM *rnd, int bits)
	{
	int i;
	prime_t mods[NUMPRIMES];
	BN_ULONG delta;
	BN_ULONG rnd_word;
	BN_ULONG size_limit;
	BN_ULONG max_delta = BN_MASK2 - primes[NUMPRIMES - 1] + 1;
	int ret = 0;
	
	OPENSSL_assert(bits <= BN_BITS2);

again:
	if (!BN_rand(rnd, bits, 1, 1)) goto err;
	
	rnd_word = BN_get_word(rnd);
	
	size_limit = (((BN_ULONG) 1) << bits) - rnd_word - 1;	
	if (size_limit < max_delta)
		{
		max_delta = size_limit;
		}

	for (i = 0; i < NUMPRIMES && primes[i] < rnd_word; i++)
		{
		mods[i] = rnd_word % primes[i];
		}

	delta = 0;

loop:
	/* We check that the candidate prime:
	 *   1) is greater than primes[i] because we shouldn't reject
	 *      3 as being a prime number because it's a multiple of
	 *      three.
	 *   2) is not a multiple of a known prime. We don't
	 *      check that rnd-1 is also coprime to all the known
	 *      primes because there aren't many small primes where
	 *      that's true. */
	for (i = 1; i < NUMPRIMES && primes[i] < rnd_word; i++)
		{
		if ((mods[i] + delta) % primes[i] == 0)
			{
			delta += 2;

			if (delta > max_delta) goto again;
			
			goto loop;
			}
		}
		
	if (!BN_add_word(rnd, delta)) goto err;
	if (BN_num_bits(rnd) != bits) goto again;
	
	ret = 1;

err:
	bn_check_top(rnd);
	return ret;
	}

int bn_probable_prime_dh(BIGNUM *rnd, int bits,
	const BIGNUM *add, const BIGNUM *rem, BN_CTX *ctx, int safe, int biased)
	{
	int i;
	uint max_rem;
	BIGNUM *t1;
	int ret = 0;

	if (safe)
		{
		max_rem = 1;
		}
	else
		{
		max_rem = 0;
		}

	BN_CTX_start(ctx);
	if ((t1 = BN_CTX_get(ctx)) == NULL) goto err;

again:
	if (!BN_rand(rnd, bits, 1, 1)) goto err;
	if (!adjust_rnd_for_dh(rnd, add, rem, t1, ctx)) goto err;

loop:
	for (i = 1; i < NUMPRIMES; i++)
		{
		/* check that rnd is a prime */
		if (BN_mod_word(rnd, (BN_ULONG)primes[i]) <= max_rem)
			{
			if (biased)
				{
				if (add == NULL)
					{
					if (!BN_add_word(rnd, 2)) goto err;
					}
				else
					{
					if (!BN_add(rnd, rnd, add)) goto err;
					}

				goto loop;
				}
			else
				{
				goto again;
				}
			}
		}

	if (BN_num_bits(rnd) != bits) goto again;

	ret = 1;

err:
	BN_CTX_end(ctx);
	bn_check_top(rnd);
	return(ret);
	}

int bn_probable_prime_dh_coprime(BIGNUM *rnd, int bits,
	const BIGNUM *add, const BIGNUM *rem, BN_CTX *ctx, int safe, int biased)
	{
	uint prm_offsets[PRIME_OFFSET_COUNT];

	if (safe)
		{
		if (bits <= safe_prime_multiplier_bits) goto fallback;

		memcpy(prm_offsets, safe_prime_offsets, sizeof safe_prime_offsets);

		return probable_prime_dh_coprime(
			rnd, bits, add, rem, ctx, prm_offsets, SAFE_PRIME_OFFSET_COUNT,
			safe_prime_multiplier, safe_prime_multiplier_bits, 1, biased);
		}
	else
		{
		if (bits <= prime_multiplier_bits) goto fallback;

		memcpy(prm_offsets, prime_offsets, sizeof prime_offsets);

		return probable_prime_dh_coprime(
			rnd, bits, add, rem, ctx, prm_offsets, PRIME_OFFSET_COUNT,
			prime_multiplier, prime_multiplier_bits, 0, biased);
		}

fallback:
	return bn_probable_prime_dh(rnd, bits, add, rem, ctx, safe, biased);
	}

static int probable_prime_dh_coprime(BIGNUM *rnd, const int bits,
	const BIGNUM *add, const BIGNUM *rem, BN_CTX *ctx,
	uint prm_offsets[PRIME_OFFSET_COUNT], uint prm_offset_count,
	const uint prm_multiplier, const int prm_multiplier_bits,
	const uint max_rem, const int biased)
	{
	int trial_output;
	uint initial_offset_index;
	BN_ULONG initial_offset;
	BIGNUM *offset_index;
	BIGNUM *offset_count;
	BIGNUM *t1;
	int ret = 0;

	BN_CTX_start(ctx);
	if ((t1 = BN_CTX_get(ctx)) == NULL) goto err;
	if ((offset_index = BN_CTX_get(ctx)) == NULL) goto err;
	if ((offset_count = BN_CTX_get(ctx)) == NULL) goto err;

	if (biased && add != NULL)
		{
		int add_word = BN_get_word(add);

		if (add_word != 2)
			{
			BN_ULONG old_offset;
			BN_ULONG offset;
			uint temp_prm_offsets[PRIME_OFFSET_COUNT];
			uint i;
			uint j = 1;

			/* we want the difference between any two offsets
			 * to be a multiple of add, but the starting point
			 * is arbitrary, so include the first offset */
			temp_prm_offsets[0] = prm_offsets[0];

			old_offset = temp_prm_offsets[0];
			for (i = 1; i < prm_offset_count; i++)
				{
				offset = prm_offsets[i];
				if ((offset - old_offset) % add_word == 0)
					{
					temp_prm_offsets[j] = offset;
					old_offset = offset;
					j++;
					}
				}

			memcpy(prm_offsets, temp_prm_offsets, sizeof temp_prm_offsets);
			prm_offset_count = j;
			}
		}

	if (!BN_set_word(offset_count, prm_offset_count)) goto err;

again:
	if (!BN_rand(rnd, bits - prm_multiplier_bits, 1, 1)) goto err;
	if (!adjust_rnd_for_dh(rnd, add, rem, t1, ctx)) goto err;

	if (!BN_mul_word(rnd, prm_multiplier)) goto err;
	if (!BN_rand_range(offset_index, offset_count)) goto err;

	initial_offset_index = BN_get_word(offset_index);
	initial_offset = prm_offsets[initial_offset_index];

	/* we now have a random number 'rand' to test. */

	if (biased)
		{
		trial_output = coprime_trial_division_biased(
			rnd, bits, prm_offsets, prm_offset_count, prm_multiplier, max_rem,
			initial_offset_index, initial_offset);
		}
	else
		{
		if (!BN_add_word(rnd, initial_offset)) goto err;
		trial_output = coprime_trial_division(rnd, max_rem);
		}

	if (trial_output == -1) goto err;
	if (!trial_output) goto again;

	ret = 1;

err:
	BN_CTX_end(ctx);
	bn_check_top(rnd);
	return ret;
	}

static int adjust_rnd_for_dh(BIGNUM *rnd, const BIGNUM *add, const BIGNUM *rem,
	BIGNUM *temp_bn, BN_CTX *ctx)
	{
	int sub;
	int ret = 0;

	/* we need ((rnd-rem) % add) == 0 */

	if (add == NULL)
		{
		sub = BN_mod_word(rnd, 2);
		if (!BN_sub_word(rnd, sub)) goto err;
		}
	else
		{
		if (!BN_mod(temp_bn, rnd, add, ctx)) goto err;
		if (!BN_sub(rnd, rnd, temp_bn)) goto err;
		}

	if (rem == NULL)
		{
		if (!BN_add_word(rnd, 1)) goto err;
		}
	else
		{
		if (!BN_add(rnd, rnd, rem)) goto err;
		}

	ret = 1;

err:
	return ret;
	}

static int coprime_trial_division(BIGNUM *rnd, const uint max_rem)
	{
	uint i;

	if (BN_num_bits(rnd) != bits) return 0;

	/* check that rnd is a prime, skipping coprimes */
	for (i = first_prime_index; i < NUMPRIMES; i++)
		{
		if (BN_mod_word(rnd, (BN_ULONG)primes[i]) <= max_rem) return 0;
		}

	return 1;
	}

static int coprime_trial_division_biased(BIGNUM *rnd, const int bits,
	uint prm_offsets[PRIME_OFFSET_COUNT], uint prm_offset_count,
	const uint prm_multiplier, const uint max_rem,
	const uint initial_offset_index, const BN_ULONG initial_offset)
	{
	prime_t mods[NUMPRIMES];
	uint i;
	uint j = initial_offset_index;
	uint base_offset = 0;
	BN_ULONG offset = initial_offset;
	BN_ULONG max_offset = BN_MASK2 - primes[NUMPRIMES - 1] + 1;

	if (BN_num_bits(rnd) != bits) return 0;

	for (i = 0; i < NUMPRIMES; i++)
		{
		mods[i] = (prime_t)BN_mod_word(rnd, (BN_ULONG)primes[i]);
		}

loop:
	/* check that rnd is a prime, skipping coprimes */
	for (i = first_prime_index; i < NUMPRIMES; i++)
		{
		if ((mods[i] + offset) % primes[i] <= max_rem)
			{
			j++;
			if (j >= prm_offset_count)
				{
				j = 0;
				base_offset += prm_multiplier;
				}

			offset = base_offset + prm_offsets[j];

			if (offset > max_offset) return 0;

			goto loop;
			}
		}

	if (!BN_add_word(rnd, offset)) return -1;

	if (BN_num_bits(rnd) != bits) return 0;

	return 1;
	}

static int witness(BIGNUM *w, const BIGNUM *a, const BIGNUM *a1,
	const BIGNUM *a1_odd, int k, BN_CTX *ctx, BN_MONT_CTX *mont)
	{
	int ret = -1;

	/* w := w^a1_odd mod a */
	if (!BN_mod_exp_mont(w, w, a1_odd, a, ctx, mont)) goto end;

	if (BN_is_one(w))
		{
		/* probably prime */
		ret = 0;
		goto end;
		}

	if (BN_cmp(w, a1) == 0)
		{
		/* w == -1 (mod a),  'a' is probably prime */
		ret = 0;
		goto end;
		}

	while (--k)
		{
		/* w := w^2 mod a */
		if (!BN_mod_mul(w, w, w, a, ctx)) goto end;

		if (BN_is_one(w))
			{
			/* 'a' is composite, otherwise a previous 'w' would
			 * have been == -1 (mod 'a') */
			ret = 1;
			goto end;
			}

		if (BN_cmp(w, a1) == 0)
			{
			/* w == -1 (mod a), 'a' is probably prime */
			ret = 0;
			goto end;
			}
		}

	/* If we get here, 'w' is the (a-1)/2-th power of the original 'w',
	 * and it is neither -1 nor +1 -- so 'a' cannot be prime */
	ret = 1;
	
end:
	bn_check_top(w);
	return ret;
	}
