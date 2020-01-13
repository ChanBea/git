/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <stddef.h>
#include "internal/cryptlib.h"

const void *otls_bsearch(const void *key, const void *base, int num,
                         int size, int (*cmp) (const void *, const void *),
                         int flags)
{
    const char *base_ = base;
    int l, h, i = 0, c = 0;
    const char *p = NULL;

    if (num == 0)
        return NULL;
    l = 0;
    h = num;
    while (l < h) {
        i = (l + h) / 2;
        p = &(base_[i * size]);
        c = (*cmp) (key, p);
        if (c < 0)
            h = i;
        else if (c > 0)
            l = i + 1;
        else
            break;
    }
    if (c != 0 && !(flags & Otls_BSEARCH_VALUE_ON_NOMATCH))
        p = NULL;
    else if (c == 0 && (flags & Otls_BSEARCH_FIRST_VALUE_ON_MATCH)) {
        while (i > 0 && (*cmp) (key, &(base_[(i - 1) * size])) == 0)
            i--;
        p = &(base_[i * size]);
    }
    return p;
}
