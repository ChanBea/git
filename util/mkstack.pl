#!/usr/local/bin/perl -w

# Search out "DECLARE_STACK_OF()" # declarations in .h and .c files,
# and create corresponding macro declarations for crypto/stack/safestack.h.

my $safestack = "crypto/stack/safestack.h";
my $do_write = 0;

foreach ( @ARGV ) {
    $do_write = 1 if $_ eq "-write";
}

my @stacklst;
my @sstacklst;
my @asn1setlst;
my @p12stklst;
my @lhashlst;
my @source = (<crypto/*.[ch]>, <crypto/*/*.[ch]>, <ssl/*.[ch]>, <apps/*.[ch]>);
foreach $file (@source) {
    next if -l $file;

    # Open the .c/.h file for reading
    open(IN, "< $file") || die "Can't open $file for reading, $!";

    while(<IN>) {
        next unless /^DECLARE_/;
        if (/^DECLARE_STACK_OF\(([^)]+)\)/) {
            push @stacklst, $1;
        }
        elsif (/^DECLARE_SPECIAL_STACK_OF\(([^,\s]+)\s*,\s*([^>\s]+)\)/) {
            push @sstacklst, [$1, $2];
        }
        elsif (/^DECLARE_LHASH_OF\(([^)]+)\)/) {
            push @lhashlst, $1;
        }
    }
    close(IN);
}

my $new_stackfile = <<'EOF';
/* automatically generated by util/mkstack.pl */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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

#ifndef HEADER_SAFESTACK_H
# define HEADER_SAFESTACK_H

# include <openssl/stack.h>

#ifdef __cplusplus
extern "C" {
#endif

# ifndef CHECKED_PTR_OF
#  define CHECKED_PTR_OF(type, p) ((void*) (1 ? p : (type*)0))
# endif

/*
 * In C++ we get problems because an explicit cast is needed from (void *) we
 * use CHECKED_STACK_OF to ensure the correct type is passed in the macros
 * below.
 */

# define CHECKED_STACK_OF(type, p) \
    ((_STACK*) (1 ? p : (STACK_OF(type)*)0))

# define CHECKED_SK_COPY_FUNC(type, p) \
    ((void *(*)(void *)) ((1 ? p : (type *(*)(const type *))0)))

# define CHECKED_SK_FREE_FUNC(type, p) \
    ((void (*)(void *)) ((1 ? p : (void (*)(type *))0)))

# define CHECKED_SK_CMP_FUNC(type, p) \
    ((int (*)(const void *, const void *)) \
        ((1 ? p : (int (*)(const type * const *, const type * const *))0)))

# define STACK_OF(type) struct stack_st_##type
# define PREDECLARE_STACK_OF(type) STACK_OF(type);

# define DECLARE_STACK_OF(type) STACK_OF(type);
# define DECLARE_SPECIAL_STACK_OF(type, type2) STACK_OF(type);

/*-
 * Strings are special: normally an lhash entry will point to a single
 * (somewhat) mutable object. In the case of strings:
 *
 * a) Instead of a single char, there is an array of chars, NUL-terminated.
 * b) The string may have be immutable.
 *
 * So, they need their own declarations. Especially important for
 * type-checking tools, such as Deputy.
 *
 * In practice, however, it appears to be hard to have a const
 * string. For now, I'm settling for dealing with the fact it is a
 * string at all.
 */
typedef char *OPENSSL_STRING;
typedef const char *OPENSSL_CSTRING;

/*-
 * Confusingly, LHASH_OF(STRING) deals with char ** throughout, but
 * STACK_OF(STRING) is really more like STACK_OF(char), only, as mentioned
 * above, instead of a single char each entry is a NUL-terminated array of
 * chars. So, we have to implement STRING specially for STACK_OF. This is
 * dealt with in the autogenerated macros below.
 */
DECLARE_SPECIAL_STACK_OF(OPENSSL_STRING, char)

/*
 * Similarly, we sometimes use a block of characters, NOT nul-terminated.
 * These should also be distinguished from "normal" stacks.
 */
typedef void *OPENSSL_BLOCK;
DECLARE_SPECIAL_STACK_OF(OPENSSL_BLOCK, void)

/*
 * This file is automatically generated by util/mkstack.pl
 * Do not edit!
 */

/*
 * SKM_sk_... stack macros are internal to safestack.h: never use them
 * directly, use sk_<type>_... instead
 */
# define SKM_sk_new(type, cmp) \
        ((STACK_OF(type) *)sk_new(CHECKED_SK_CMP_FUNC(type, cmp)))
# define SKM_sk_new_null(type) \
        ((STACK_OF(type) *)sk_new_null())
# define SKM_sk_free(type, st) \
        sk_free(CHECKED_STACK_OF(type, st))
# define SKM_sk_num(type, st) \
        sk_num(CHECKED_STACK_OF(type, st))
# define SKM_sk_value(type, st,i) \
        ((type *)sk_value(CHECKED_STACK_OF(type, st), i))
# define SKM_sk_set(type, st,i,val) \
        sk_set(CHECKED_STACK_OF(type, st), i, CHECKED_PTR_OF(type, val))
# define SKM_sk_zero(type, st) \
        sk_zero(CHECKED_STACK_OF(type, st))
# define SKM_sk_push(type, st, val) \
        sk_push(CHECKED_STACK_OF(type, st), CHECKED_PTR_OF(type, val))
# define SKM_sk_unshift(type, st, val) \
        sk_unshift(CHECKED_STACK_OF(type, st), CHECKED_PTR_OF(type, val))
# define SKM_sk_find(type, st, val) \
        sk_find(CHECKED_STACK_OF(type, st), CHECKED_PTR_OF(type, val))
# define SKM_sk_find_ex(type, st, val) \
        sk_find_ex(CHECKED_STACK_OF(type, st), \
                   CHECKED_PTR_OF(type, val))
# define SKM_sk_delete(type, st, i) \
        (type *)sk_delete(CHECKED_STACK_OF(type, st), i)
# define SKM_sk_delete_ptr(type, st, ptr) \
        (type *)sk_delete_ptr(CHECKED_STACK_OF(type, st), CHECKED_PTR_OF(type, ptr))
# define SKM_sk_insert(type, st,val, i) \
        sk_insert(CHECKED_STACK_OF(type, st), CHECKED_PTR_OF(type, val), i)
# define SKM_sk_set_cmp_func(type, st, cmp) \
        ((int (*)(const type * const *,const type * const *)) \
        sk_set_cmp_func(CHECKED_STACK_OF(type, st), CHECKED_SK_CMP_FUNC(type, cmp)))
# define SKM_sk_dup(type, st) \
        (STACK_OF(type) *)sk_dup(CHECKED_STACK_OF(type, st))
# define SKM_sk_pop_free(type, st, free_func) \
        sk_pop_free(CHECKED_STACK_OF(type, st), CHECKED_SK_FREE_FUNC(type, free_func))
# define SKM_sk_deep_copy(type, st, copy_func, free_func) \
        (STACK_OF(type) *)sk_deep_copy(CHECKED_STACK_OF(type, st), CHECKED_SK_COPY_FUNC(type, copy_func), CHECKED_SK_FREE_FUNC(type, free_func))
# define SKM_sk_shift(type, st) \
        (type *)sk_shift(CHECKED_STACK_OF(type, st))
# define SKM_sk_pop(type, st) \
        (type *)sk_pop(CHECKED_STACK_OF(type, st))
# define SKM_sk_sort(type, st) \
        sk_sort(CHECKED_STACK_OF(type, st))
# define SKM_sk_is_sorted(type, st) \
        sk_is_sorted(CHECKED_STACK_OF(type, st))

# define SKM_ASN1_SET_OF_d2i(type, st, pp, length, d2i_func, free_func, ex_tag, ex_class) \
  (STACK_OF(type) *)d2i_ASN1_SET( \
                                (STACK_OF(OPENSSL_BLOCK) **)CHECKED_PTR_OF(STACK_OF(type)*, st), \
                                pp, length, \
                                CHECKED_D2I_OF(type, d2i_func), \
                                CHECKED_SK_FREE_FUNC(type, free_func), \
                                ex_tag, ex_class)
# define SKM_ASN1_SET_OF_i2d(type, st, pp, i2d_func, ex_tag, ex_class, is_set) \
        i2d_ASN1_SET(CHECKED_STACK_OF(type, st), pp, \
                                CHECKED_I2D_OF(type, i2d_func), \
                                ex_tag, ex_class, is_set)

# define SKM_ASN1_seq_pack(type, st, i2d_func, buf, len) \
        ASN1_seq_pack(CHECKED_PTR_OF(STACK_OF(type), st), \
                        CHECKED_I2D_OF(type, i2d_func), buf, len)
# define SKM_ASN1_seq_unpack(type, buf, len, d2i_func, free_func) \
        (STACK_OF(type) *)ASN1_seq_unpack(buf, \
                              len, CHECKED_D2I_OF(type, d2i_func), \
                              CHECKED_SK_FREE_FUNC(type, free_func))
# define SKM_PKCS12_decrypt_d2i(type, algor, d2i_func, free_func, pass, passlen, oct, seq) \
        (STACK_OF(type) *)PKCS12_decrypt_d2i(algor, \
                                CHECKED_D2I_OF(type, d2i_func), \
                                CHECKED_SK_FREE_FUNC(type, free_func), \
                                pass, passlen, oct, seq)
EOF

my $old_stackfile;
{
    local $/ = undef;
    open(IN, "$safestack") || die "Can't open $safestack, $!";
    $old_stackfile = <IN>;
    close(IN);
}

my $type_thing;
foreach $type_thing (sort @stacklst) {
    $new_stackfile .= <<EOF;

# define sk_${type_thing}_new(cmp) SKM_sk_new($type_thing, (cmp))
# define sk_${type_thing}_new_null() SKM_sk_new_null($type_thing)
# define sk_${type_thing}_free(st) SKM_sk_free($type_thing, (st))
# define sk_${type_thing}_num(st) SKM_sk_num($type_thing, (st))
# define sk_${type_thing}_value(st, i) SKM_sk_value($type_thing, (st), (i))
# define sk_${type_thing}_set(st, i, val) SKM_sk_set($type_thing, (st), (i), (val))
# define sk_${type_thing}_zero(st) SKM_sk_zero($type_thing, (st))
# define sk_${type_thing}_push(st, val) SKM_sk_push($type_thing, (st), (val))
# define sk_${type_thing}_unshift(st, val) SKM_sk_unshift($type_thing, (st), (val))
# define sk_${type_thing}_find(st, val) SKM_sk_find($type_thing, (st), (val))
# define sk_${type_thing}_find_ex(st, val) SKM_sk_find_ex($type_thing, (st), (val))
# define sk_${type_thing}_delete(st, i) SKM_sk_delete($type_thing, (st), (i))
# define sk_${type_thing}_delete_ptr(st, ptr) SKM_sk_delete_ptr($type_thing, (st), (ptr))
# define sk_${type_thing}_insert(st, val, i) SKM_sk_insert($type_thing, (st), (val), (i))
# define sk_${type_thing}_set_cmp_func(st, cmp) SKM_sk_set_cmp_func($type_thing, (st), (cmp))
# define sk_${type_thing}_dup(st) SKM_sk_dup($type_thing, st)
# define sk_${type_thing}_pop_free(st, free_func) SKM_sk_pop_free($type_thing, (st), (free_func))
# define sk_${type_thing}_deep_copy(st, copy_func, free_func) SKM_sk_deep_copy($type_thing, (st), (copy_func), (free_func))
# define sk_${type_thing}_shift(st) SKM_sk_shift($type_thing, (st))
# define sk_${type_thing}_pop(st) SKM_sk_pop($type_thing, (st))
# define sk_${type_thing}_sort(st) SKM_sk_sort($type_thing, (st))
# define sk_${type_thing}_is_sorted(st) SKM_sk_is_sorted($type_thing, (st))
EOF
}

foreach $type_thing (sort @sstacklst) {
    my $t1 = $type_thing->[0];
    my $t2 = $type_thing->[1];
    $new_stackfile .= <<EOF;

# define sk_${t1}_new(cmp) ((STACK_OF($t1) *)sk_new(CHECKED_SK_CMP_FUNC($t2, cmp)))
# define sk_${t1}_new_null() ((STACK_OF($t1) *)sk_new_null())
# define sk_${t1}_push(st, val) sk_push(CHECKED_STACK_OF($t1, st), CHECKED_PTR_OF($t2, val))
# define sk_${t1}_find(st, val) sk_find(CHECKED_STACK_OF($t1, st), CHECKED_PTR_OF($t2, val))
# define sk_${t1}_value(st, i) (($t1)sk_value(CHECKED_STACK_OF($t1, st), i))
# define sk_${t1}_num(st) SKM_sk_num($t1, st)
# define sk_${t1}_pop_free(st, free_func) sk_pop_free(CHECKED_STACK_OF($t1, st), CHECKED_SK_FREE_FUNC($t2, free_func))
# define sk_${t1}_deep_copy(st, copy_func, free_func) ((STACK_OF($t1) *)sk_deep_copy(CHECKED_STACK_OF($t1, st), CHECKED_SK_COPY_FUNC($t2, copy_func), CHECKED_SK_FREE_FUNC($t2, free_func)))
# define sk_${t1}_insert(st, val, i) sk_insert(CHECKED_STACK_OF($t1, st), CHECKED_PTR_OF($t2, val), i)
# define sk_${t1}_free(st) SKM_sk_free(${t1}, st)
# define sk_${t1}_set(st, i, val) sk_set(CHECKED_STACK_OF($t1, st), i, CHECKED_PTR_OF($t2, val))
# define sk_${t1}_zero(st) SKM_sk_zero($t1, (st))
# define sk_${t1}_unshift(st, val) sk_unshift(CHECKED_STACK_OF($t1, st), CHECKED_PTR_OF($t2, val))
# define sk_${t1}_find_ex(st, val) sk_find_ex((_STACK *)CHECKED_CONST_PTR_OF(STACK_OF($t1), st), CHECKED_CONST_PTR_OF($t2, val))
# define sk_${t1}_delete(st, i) SKM_sk_delete($t1, (st), (i))
# define sk_${t1}_delete_ptr(st, ptr) ($t1 *)sk_delete_ptr(CHECKED_STACK_OF($t1, st), CHECKED_PTR_OF($t2, ptr))
# define sk_${t1}_set_cmp_func(st, cmp)  \\
        ((int (*)(const $t2 * const *,const $t2 * const *)) \\
        sk_set_cmp_func(CHECKED_STACK_OF($t1, st), CHECKED_SK_CMP_FUNC($t2, cmp)))
# define sk_${t1}_dup(st) SKM_sk_dup($t1, st)
# define sk_${t1}_shift(st) SKM_sk_shift($t1, (st))
# define sk_${t1}_pop(st) ($t2 *)sk_pop(CHECKED_STACK_OF($t1, st))
# define sk_${t1}_sort(st) SKM_sk_sort($t1, (st))
# define sk_${t1}_is_sorted(st) SKM_sk_is_sorted($t1, (st))
EOF
}

foreach $type_thing (sort @lhashlst) {
    my $lc_tt = lc $type_thing;
    $new_stackfile .= <<EOF;

# define lh_${type_thing}_new() LHM_lh_new(${type_thing},${lc_tt})
# define lh_${type_thing}_insert(lh,inst) LHM_lh_insert(${type_thing},lh,inst)
# define lh_${type_thing}_retrieve(lh,inst) LHM_lh_retrieve(${type_thing},lh,inst)
# define lh_${type_thing}_delete(lh,inst) LHM_lh_delete(${type_thing},lh,inst)
# define lh_${type_thing}_doall(lh,fn) LHM_lh_doall(${type_thing},lh,fn)
# define lh_${type_thing}_doall_arg(lh,fn,arg_type,arg) \\
  LHM_lh_doall_arg(${type_thing},lh,fn,arg_type,arg)
# define lh_${type_thing}_error(lh) LHM_lh_error(${type_thing},lh)
# define lh_${type_thing}_num_items(lh) LHM_lh_num_items(${type_thing},lh)
# define lh_${type_thing}_down_load(lh) LHM_lh_down_load(${type_thing},lh)
# define lh_${type_thing}_node_stats_bio(lh,out) \\
  LHM_lh_node_stats_bio(${type_thing},lh,out)
# define lh_${type_thing}_node_usage_stats_bio(lh,out) \\
  LHM_lh_node_usage_stats_bio(${type_thing},lh,out)
# define lh_${type_thing}_stats_bio(lh,out) \\
  LHM_lh_stats_bio(${type_thing},lh,out)
# define lh_${type_thing}_free(lh) LHM_lh_free(${type_thing},lh)
EOF
}

$new_stackfile .= <<'EOF';

# ifdef  __cplusplus
}
# endif
#endif
EOF

if ($new_stackfile eq $old_stackfile) {
    print "No changes to $safestack.\n";
}
elsif ($do_write) {
    print "Writing new $safestack.\n";
    open OUT, ">$safestack" || die "Can't open $safestack for writing, $!";
    print OUT $new_stackfile;
    close OUT;
}

exit 0;
