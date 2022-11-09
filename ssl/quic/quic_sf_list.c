/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/uint_set.h"
#include "internal/common.h"
#include "internal/quic_record_rx_wrap.h"
#include "internal/quic_sf_list.h"

/*
 * Stream frame list
 * =================
 *
 * This data structure uses supports similar operations as uint64 set but
 * it has slightly different invariants and also carries data associated with
 * the ranges in the list.
 *
 * Operations:
 *   Insert frame (optimized insertion at the beginning and at the end).
 *   Iterated peek into the frame(s) from the beginning.
 *   Dropping frames from the beginning up to an offset (exclusive).
 *
 * Invariant: The frames in the list are sorted by the start and end bounds.
 * Invariant: There are no fully overlapping frames or frames that would
 *            be fully encompassed by another frame in the list.
 * Invariant: No frame has start > end.
 * Invariant: The range start is inclusive the end is exclusive to be
 *            able to mark an empty frame.
 * Invariant: The offset never points further than into the first frame.
 */

struct stream_frame_st {
    struct stream_frame_st *prev, *next;
    UINT_RANGE range;
    OSSL_QRX_PKT_WRAP *pkt;
    const unsigned char *data;
};

static void stream_frame_free(SFRAME_LIST *fl, STREAM_FRAME *sf)
{
    ossl_qrx_pkt_wrap_free(fl->qrx, sf->pkt);
    OPENSSL_free(sf);
}

static STREAM_FRAME *stream_frame_new(UINT_RANGE *range, OSSL_QRX_PKT_WRAP *pkt,
                                      const unsigned char *data)
{
    STREAM_FRAME *sf = OPENSSL_zalloc(sizeof(*sf));

    if (pkt != NULL && !ossl_qrx_pkt_wrap_up_ref(pkt)) {
        OPENSSL_free(sf);
        return NULL;
    }

    sf->range = *range;
    sf->pkt = pkt;
    sf->data = data;

    return sf;
}

void ossl_sframe_list_init(SFRAME_LIST *fl, OSSL_QRX *qrx)
{
    memset(fl, 0, sizeof(*fl));
    fl->qrx = qrx;
}

void ossl_sframe_list_destroy(SFRAME_LIST *fl)
{
    STREAM_FRAME *sf, *next_frame;

    for (sf = fl->head; sf != NULL; sf = next_frame) {
        next_frame = sf->next;
        stream_frame_free(fl, sf);
    }
}

static int append_frame(SFRAME_LIST *fl, UINT_RANGE *range,
                        OSSL_QRX_PKT_WRAP *pkt,
                        const unsigned char *data)
{
    STREAM_FRAME *new_frame;

    if ((new_frame = stream_frame_new(range, pkt, data)) == NULL)
        return 0;
    new_frame->prev = fl->tail;
    if (fl->tail != NULL)
        fl->tail->next = new_frame;
    fl->tail = new_frame;
    ++fl->num_frames;
    return 1;
}

int ossl_sframe_list_insert(SFRAME_LIST *fl, UINT_RANGE *range,
                            OSSL_QRX_PKT_WRAP *pkt,
                            const unsigned char *data, int fin)
{
    STREAM_FRAME *sf, *new_frame, *prev_frame, *next_frame;

    /* nothing there yet */
    if (fl->tail == NULL) {
        if ((fin && fl->offset > range->end)
            || (fl->fin && fl->offset < range->end)) {
            /* TODO(QUIC): protocol violation: FINAL_SIZE_ERROR */
            return 0;
        }
        fl->fin = fin || fl->fin;

        if (fl->offset >= range->end)
            return 1;

        fl->tail = fl->head = stream_frame_new(range, pkt, data);
        if (fl->tail == NULL)
            return 0;
        ++fl->num_frames;
        return 1;
    }

    if ((fin && fl->tail->range.end > range->end)
        || (fl->fin && fl->tail->range.end < range->end)) {
        /* TODO(QUIC): protocol violation: FINAL_SIZE_ERROR */
        return 0;
    }
    fl->fin = fin || fl->fin;

    if (fl->offset >= range->end)
        return 1;

    /* TODO(QUIC): Check for fl->num_frames and start copying if too many */

    /* optimize insertion at the end */
    if (fl->tail->range.start < range->start) {
        if (fl->tail->range.end >= range->end) {
            return 1;
        }
        return append_frame(fl, range, pkt, data);
    }

    prev_frame = NULL;
    for (sf = fl->head; sf != NULL && sf->range.start < range->start;
         sf = sf->next)
        prev_frame = sf;

    if (prev_frame != NULL && prev_frame->range.end >= range->end) {
        return 1;
    }

    if (sf == NULL)
        return append_frame(fl, range, pkt, data);

    /*
     * Now we must create a new frame although in the end we might drop it,
     * because we will be potentially dropping existing overlapping frames.
     */
    new_frame = stream_frame_new(range, pkt, data);
    if (new_frame == NULL)
        return 0;

    for (next_frame = sf;
         next_frame != NULL && next_frame->range.end <= range->end;) {
        STREAM_FRAME *drop_frame = next_frame;

        next_frame = next_frame->next;
        if (next_frame != NULL)
            next_frame->prev = drop_frame->prev;
        if (prev_frame != NULL)
            prev_frame->next = drop_frame->next;
        if (fl->head == drop_frame)
            fl->head = next_frame;
        if (fl->tail == drop_frame)
            fl->tail = prev_frame;
        --fl->num_frames;
        stream_frame_free(fl, drop_frame);
    }
    if (next_frame != NULL) {
        /* check whether the new_frame is redundant because there is no gap */
        if (prev_frame != NULL
            && next_frame->range.start <= prev_frame->range.end) {
            stream_frame_free(fl, new_frame);
            return 1;
        }
        next_frame->prev = new_frame;
    } else {
        fl->tail = new_frame;
    }
    new_frame->next = next_frame;
    new_frame->prev = prev_frame;
    if (prev_frame != NULL)
        prev_frame->next = new_frame;
    else
        fl->head = new_frame;
    ++fl->num_frames;
    return 1;
}

int ossl_sframe_list_peek(const SFRAME_LIST *fl, void **iter,
                          UINT_RANGE *range, const unsigned char **data,
                          int *fin)
{
    STREAM_FRAME *sf = *iter;
    uint64_t start;

    if (sf == NULL) {
        start = fl->offset;
        sf = fl->head;
    } else {
        start = sf->range.end;
        sf = sf->next;
    }

    range->start = start;

    if (sf == NULL || sf->range.start > start
        || !ossl_assert(start < sf->range.end)) {
        range->end = start;
        *data = NULL;
        *iter = NULL;
        /* set fin only if we are at the end */
        *fin = sf == NULL ? fl->fin : 0;
        return 0;
    }

    range->end = sf->range.end;
    *data = sf->data + (start - sf->range.start);
    *fin = sf->next == NULL ? fl->fin : 0;
    *iter = sf;
    return 1;
}

int ossl_sframe_list_drop_frames(SFRAME_LIST *fl, uint64_t limit)
{
    STREAM_FRAME *sf;

    /* offset cannot move back or past the data received */
    if (!ossl_assert(limit >= fl->offset)
        || !ossl_assert(fl->tail == NULL
                        || limit <= fl->tail->range.end)
        || !ossl_assert(fl->tail != NULL
                        || limit == fl->offset))
        return 0;

    fl->offset = limit;

    for (sf = fl->head; sf != NULL && sf->range.end <= limit;) {
        STREAM_FRAME *drop_frame = sf;

        sf = sf->next;
        --fl->num_frames;
        stream_frame_free(fl, drop_frame);
    }
    fl->head = sf;
    if (sf != NULL)
        sf->prev = NULL;
    else
        fl->tail = NULL;
    return 1;
}
