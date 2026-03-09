/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES.
 * Copyright (c) 2022-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/* Source file for device part of packet processing sample.
 * Contain functions for initialize contexts of internal queues,
 * read, check, change and resend the packet and wait for another.
 */

/* Shared header file with utilities for samples.
 * The file also have includes to flexio_dev_ver.h and flexio_dev.h
 * The include must be placed first to correctly handle the version.
 */
#include "com_dev.h"
#include <libflexio-dev/flexio_dev_err.h>
#include <libflexio-dev/flexio_dev_queue_access.h>
#include <libflexio-libc/string.h>
#include <stddef.h>
#include <dpaintrin.h>
/* Shared header file for packet processor sample */
#include "../flexio_packet_processor_com.h"

/* Mask for CQ index */
#define CQ_IDX_MASK ((1 << LOG_CQ_DEPTH) - 1)
/* Mask for RQ index */
#define RQ_IDX_MASK ((1 << LOG_RQ_DEPTH) - 1)
/* Mask for SQ index */
#define SQ_IDX_MASK ((1 << (LOG_SQ_DEPTH + LOG_SQE_NUM_SEGS)) - 1)
/* Mask for data index */
#define DATA_IDX_MASK ((1 << (LOG_SQ_DEPTH)) - 1)

/* Per-thread DPA application context. Indexed by thread_index. */
struct app_device_ctx {
	cq_ctx_t  rq_cq_ctx;    /* RQ CQ */ //40B
	rq_ctx_t  rq_ctx;       /* RQ */ //24B
	sq_ctx_t  sq_ctx;       /* SQ */ //24B
	cq_ctx_t  sq_cq_ctx;    /* SQ CQ */ //40B
	dt_ctx_t  dt_ctx;       /* SQ Data ring */ //16B

	uint64_t rqd_haddr_base;     /* host VA base of RQ data buffer */
	uint64_t sqd_haddr_base;     /* host VA base of SQ data buffer */
	uint64_t rqcq_haddr_base;        /* host VA of RQ CQ ring (hostcq mode) */

	/* Per-invocation DPA window pointers (set at start of each handler call) */
	flexio_uintptr_t rqd_dpa_base;
	flexio_uintptr_t sqd_dpa_base;

	uint32_t rqd_mkey;           /* ibv lkey for RQ data buffer */
	uint32_t sqd_mkey;           /* ibv lkey for SQ data buffer */ // here, 192B

	uint64_t  packets_count; 
	uint64_t  comp_packets_count;

	/* lkey - local memory key (DPA flexio mkey or ibv lkey depending on mode) */
	uint32_t  lkey;
	/* Thread index - mirrors host-side assignment */
	uint32_t  thread_index;

	/* Host buffer mode fields (only meaningful when hostbuf_enabled == 1) */
	uint32_t window_id;          /* FlexIO window ID */

    uint8_t rsvd[36];
} __attribute__((__packed__, aligned(64)));

/* Static array of per-thread contexts. Each event handler is pinned to a dedicated EU,
 * so EU i only ever accesses app_ctxs[i] — no locking required.
 */
static struct app_device_ctx app_ctxs[APP_MAX_DPA_THREADS];

FLEXIO_DEV_ALWAYS_INLINE flexio_dev_status_t flexio_dev_dbr_rq_inc_pi_value(uint32_t *rq_dbr, uint32_t value)
{
	uint32_t rq_rcv_counter;

	rq_rcv_counter = be32_to_cpu(*rq_dbr);
	*rq_dbr = cpu_to_be32((rq_rcv_counter + value) & 0xffff);
	return FLEXIO_DEV_STATUS_SUCCESS;
}

static void dbr_rq_inc_pi_value_with_one_padding(rq_ctx_t *rq_ctx, uint32_t value) {
    if (rq_ctx->first_doorbelled)
        flexio_dev_dbr_rq_inc_pi_value(rq_ctx->rq_dbr, value);
    else {
        flexio_dev_dbr_rq_inc_pi_value(rq_ctx->rq_dbr, value - 1U);
        rq_ctx->first_doorbelled = 1;
    }
}

/* Initialize a per-thread context from the host data.
 *  ctx            - pointer to the app_device_ctx to initialize.
 *  data_from_host - pointer to host2dev_packet_processor_data from host.
 */
static void app_ctx_init(struct app_device_ctx *ctx,
			  struct host2dev_packet_processor_data *data_from_host)
{
	ctx->packets_count = 0;
    ctx->comp_packets_count = 0;
	ctx->lkey = data_from_host->sq_transf.wqd_mkey_id;
	ctx->thread_index = data_from_host->thread_index;

    #ifdef HOSTBUF
	/* Initialize host buffer mode fields. */
    ctx->window_id = data_from_host->window_id;
    ctx->rqd_mkey = data_from_host->rq_transf.wqd_mkey_id;
    ctx->sqd_mkey = data_from_host->sq_transf.wqd_mkey_id;
    ctx->rqd_haddr_base = data_from_host->rq_transf.wqd_daddr;
    ctx->sqd_haddr_base = data_from_host->sq_transf.wqd_daddr;
    #endif

    #ifdef HOSTCQ
	/* When hostcq is on, the CQ ring is in host memory within the combined buffer.
	 * Save the host VA; cq_ring/cqe pointers are updated per-invocation after
	 * window_ptr_acquire (window state resets between invocations).
	 */
    ctx->rqcq_haddr_base = data_from_host->rq_cq_transf.cq_ring_daddr;
    #endif

	/* Set context for RQ's CQ.
	 * When hostcq: pass 0 for cq_ring_daddr — it is set to the window-mapped
	 * DPA address every invocation in the per-invocation window block below.
	 */
	com_cq_ctx_init(&ctx->rq_cq_ctx,
			data_from_host->rq_cq_transf.cq_num,
			data_from_host->rq_cq_transf.log_cq_depth,
            #ifdef HOSTCQ
			0,
            #else
			data_from_host->rq_cq_transf.cq_ring_daddr,
            #endif
			data_from_host->rq_cq_transf.cq_dbr_daddr);

	/* Set context for RQ */
	com_rq_ctx_init(&ctx->rq_ctx,
			data_from_host->rq_transf.wq_num,
			data_from_host->rq_transf.wq_ring_daddr,
			data_from_host->rq_transf.wq_dbr_daddr);

	/* Set context for SQ */
	com_sq_ctx_init(&ctx->sq_ctx,
			data_from_host->sq_transf.wq_num,
			data_from_host->sq_transf.wq_ring_daddr);

	/* Set context for SQ's CQ */
	com_cq_ctx_init(&ctx->sq_cq_ctx,
			data_from_host->sq_cq_transf.cq_num,
			data_from_host->sq_cq_transf.log_cq_depth,
			data_from_host->sq_cq_transf.cq_ring_daddr,
			data_from_host->sq_cq_transf.cq_dbr_daddr);

	/* Set context for data */
	com_dt_ctx_init(&ctx->dt_ctx, data_from_host->sq_transf.wqd_daddr);
}

#if CQE_COMP==1
static void decompress_packet(struct app_device_ctx *ctx) {
    struct flexio_dev_cqe64 *mini_cqe_block = ctx->rq_cq_ctx.cqe;
	uint32_t cq_idx_mask = L2M(ctx->rq_cq_ctx.log_cq_depth);
	struct flexio_dev_cqe64 *title_cqe = &ctx->rq_cq_ctx.cq_ring[(ctx->rq_cq_ctx.cq_idx - 1U) & cq_idx_mask];

    uint32_t mini_cqe_num = (uint32_t) flexio_dev_comp_cqe_get_num_comp_cqes(mini_cqe_block);

    uint64_t mini_cqes[7] = {0};
    for (uint32_t i = 0; i < mini_cqe_num; i++) {
        mini_cqes[i] = flexio_dev_comp_cqe_get_comp_cqe(ctx->rq_cq_ctx.cqe, i);
    }

    struct flexio_dev_cqe64 *current_cqe = NULL;
    uint8_t current_own_bit = flexio_dev_cqe_get_owner(title_cqe);
    for (uint32_t i = 0; i < mini_cqe_num; i++) {
        current_cqe = &ctx->rq_cq_ctx.cq_ring[(ctx->rq_cq_ctx.cq_idx + i) & CQ_IDX_MASK];
        current_own_bit = ((ctx->rq_cq_ctx.cq_idx + i) & CQ_IDX_MASK) ? current_own_bit : !current_own_bit;
        
        memcpy(current_cqe, title_cqe, 64);

        current_cqe->byte_cnt = (__be32) (mini_cqes[i] >> 32) & 0xFFFFFFFF;
        current_cqe->rsvd00[3] = (__be32) (mini_cqes[i]) & 0xFFFFFFFF;
        current_cqe->wqe_counter = (__be16) cpu_to_be16(be16_to_cpu(title_cqe->wqe_counter) + i + 1U);

        current_cqe->op_own = (title_cqe->op_own & (~0x01)) | (current_own_bit & 0x01);
    }

    ctx->comp_packets_count += mini_cqe_num;

    #ifdef HOSTCQ
    __dpa_thread_window_read_inv();
    #endif
}
#endif

/* process packet - read it, swap MAC addresses, modify it, create a send WQE and send it back.
 *  ctx - pointer to the per-thread app_device_ctx.
 */
#ifndef RXONLY
static void process_packet(struct app_device_ctx *ctx)
{
	/* RX packet handling variables */
	struct flexio_dev_wqe_rcv_data_seg *rwqe;
	/* RQ WQE index */
	uint32_t rq_wqe_idx;
	/* Pointer to RQ data (DPA address — either DPA heap or window-mapped host memory) */
	char *rq_data;

	/* TX packet handling variables */
	union flexio_dev_sqe_seg *swqe;
	/* Pointer to SQ data (DPA address — either DPA heap or window-mapped host memory) */
	char *sq_data;
	/* Host VA of the SQ slot — used in WQE when hostbuf_enabled (NIC reads via IOMMU) */
	uint64_t sq_haddr;

	/* Size of the data */
	uint32_t data_sz;

	/* Extract relevant data from the CQE */
	rq_wqe_idx = flexio_dev_cqe_get_wqe_counter(ctx->rq_cq_ctx.cqe);
	data_sz = flexio_dev_cqe_get_byte_cnt(ctx->rq_cq_ctx.cqe);

	/* Get the RQ WQE pointed to by the CQE */
	rwqe = &ctx->rq_ctx.rq_ring[rq_wqe_idx & RQ_IDX_MASK];

    #ifdef HOSTBUF
    /* Host buffer mode: WQE contains host VA; translate to DPA window pointer. */
    uint64_t rq_haddr = (uint64_t)flexio_dev_rwqe_get_addr(rwqe);
    rq_data = (char *)(ctx->rqd_dpa_base + (rq_haddr - ctx->rqd_haddr_base));

    #ifdef ZEROCOPY
    sq_data = rq_data;
    sq_haddr = rq_haddr;
    #else
    /* Normal path: copy to the next SQ data slot. */
    uint32_t sq_slot = ctx->dt_ctx.tx_buff_idx & DATA_IDX_MASK;
    sq_haddr = ctx->sqd_haddr_base + ((uint64_t)sq_slot << LOG_WQD_CHUNK_BSIZE);
    sq_data = (char *)(ctx->sqd_dpa_base + ((uint64_t)sq_slot << LOG_WQD_CHUNK_BSIZE));
    ctx->dt_ctx.tx_buff_idx++;
    #endif
    #else
    /* DPA buffer mode: pointers are DPA heap addresses, usable directly. */
    rq_data = flexio_dev_rwqe_get_addr(rwqe);
    sq_haddr = 0; /* unused in DPA mode */
    #ifdef ZEROCOPY
    /* Zero-copy: send directly from the RQ buffer. */
    sq_data = rq_data;
    #else
    /* Normal path: copy to the next SQ data slot. */
    sq_data = get_next_dte(&ctx->dt_ctx, DATA_IDX_MASK, LOG_WQD_CHUNK_BSIZE);
    #endif
    #endif

	/* Copy received packet to sq_data (skipped in zero-copy mode). */
    #ifndef ZEROCOPY
    memcpy(sq_data, rq_data, data_sz);
    #endif

	/* swap mac address */
	swap_macs(sq_data);

	/* Primitive validation, that packet is our hardcoded */
	if (data_sz == 65) {
		/* modify UDP payload */
		memcpy(sq_data + 0x2a, "  Event demo***************", 65 - 0x2a);

		/* Set hexadecimal value by the index */
		sq_data[0x2a] = "0123456789abcdef"[ctx->dt_ctx.tx_buff_idx & 0xf];
	}

	/* Take first segment for SQ WQE (3 segments will be used) */
	swqe = get_next_sqe(&ctx->sq_ctx, SQ_IDX_MASK);

	/* Fill out 1-st segment (Control) */
	flexio_dev_swqe_seg_ctrl_set(swqe, ctx->sq_ctx.sq_pi, ctx->sq_ctx.sq_number,
				     FLEXIO_CTRL_SEG_CE_CQE_ON_CQE_ERROR,
				     FLEXIO_CTRL_SEG_TYPE_SEND_EN);

	/* Fill out 2-nd segment (Ethernet) */
	swqe = get_next_sqe(&ctx->sq_ctx, SQ_IDX_MASK);
	flexio_dev_swqe_seg_eth_set(swqe, 0, 0, 0, NULL);

	/* Fill out 3-rd segment (Data).
	 * hostbuf: WQE addr = host VA (NIC uses lkey for IOMMU); must flush window first.
	 * DPA buf: WQE addr = DPA heap pointer (NIC uses flexio mkey). */
	swqe = get_next_sqe(&ctx->sq_ctx, SQ_IDX_MASK);
    #ifdef HOSTBUF
    /* Flush window writes so NIC sees the packet data in host memory. */
    __dpa_thread_window_writeback();
    flexio_dev_swqe_seg_mem_ptr_data_set(swqe, data_sz, ctx->lkey, sq_haddr);
    #else
    flexio_dev_swqe_seg_mem_ptr_data_set(swqe, data_sz, ctx->lkey, (uint64_t)sq_data);
    #endif

	/* Send WQE is 4 WQEBBs need to skip the 4-th segment */
	swqe = get_next_sqe(&ctx->sq_ctx, SQ_IDX_MASK);

	/* Ring DB */
	__dpa_thread_fence(__DPA_MEMORY, __DPA_W, __DPA_W);
	flexio_dev_qp_sq_ring_db(++ctx->sq_ctx.sq_pi, ctx->sq_ctx.sq_number);
}
#endif

static void update_data_from_host_report(struct host2dev_packet_processor_data *data_from_host, struct app_device_ctx *ctx) {
    data_from_host->report_packets_count = ctx->packets_count;
    data_from_host->report_comp_packets_count = ctx->comp_packets_count;
    data_from_host->heartbeat++;
}

/* Entry point function that host side calls for execution.
 *  thread_arg - pointer to the host2dev_packet_processor_data structure
 *     to transfer data from the host side.
 */
flexio_dev_event_handler_t flexio_pp_dev;
__dpa_global__ void flexio_pp_dev(uint64_t thread_arg)
{
	struct host2dev_packet_processor_data *data_from_host = (void *)thread_arg;
	struct app_device_ctx *ctx;

	/* Validate thread index is in range. */
	if (data_from_host->thread_index >= APP_MAX_DPA_THREADS) {
		flexio_dev_thread_reschedule();
		return;
	}

	/* Select per-thread context by thread_index. Each event handler is pinned to a
	 * dedicated EU (FLEXIO_AFFINITY_STRICT on the host), so no concurrent access occurs.
	 */
	ctx = &app_ctxs[data_from_host->thread_index];

	/* If the thread is executed for first time, then initialize the context. */
	if (!data_from_host->not_first_run) {
		app_ctx_init(ctx, data_from_host);
		data_from_host->not_first_run = 1;
	}

    #ifdef HOSTBUF
	/* Configure the window every invocation (window state resets between invocations).
	 * RQ and SQ data share a single combined host buffer registered under one lkey,
	 * so only FLEXIO_DEV_WINDOW_ENTITY_0 is needed.
	 * Acquire a DPA window pointer for the combined buffer base (= RQ half start),
	 * then derive the SQ base pointer as an offset within the same window.
	 */
    flexio_uintptr_t combined_dpa_base;

    flexio_dev_window_config(FLEXIO_DEV_WINDOW_ENTITY_0, ctx->window_id, ctx->rqd_mkey);
    flexio_dev_window_ptr_acquire(FLEXIO_DEV_WINDOW_ENTITY_0, ctx->rqd_haddr_base, &combined_dpa_base);
    ctx->rqd_dpa_base = combined_dpa_base;
    ctx->sqd_dpa_base = combined_dpa_base + (ctx->sqd_haddr_base - ctx->rqd_haddr_base);

    #ifdef HOSTCQ
    /* When hostcq is on, the CQ ring lives in host memory within the combined
    * buffer.  Window state resets each invocation, so recompute the DPA window
    * pointer to the CQ ring and update cq_ring / cqe accordingly.
    */
    uint32_t mask = L2M(ctx->rq_cq_ctx.log_cq_depth);
    ctx->rq_cq_ctx.cq_ring = (struct flexio_dev_cqe64 *)(uintptr_t)
        (combined_dpa_base + (ctx->rqcq_haddr_base - ctx->rqd_haddr_base));
    ctx->rq_cq_ctx.cqe = &ctx->rq_cq_ctx.cq_ring[ctx->rq_cq_ctx.cq_idx & mask];
    #endif
    #endif

    uint64_t last_packet_count = ctx->packets_count;
    
    uint64_t last_doorbelled_packet_count = ctx->packets_count;

	/* Poll CQ until the package is received. */
	while (1) {
        volatile uint8_t *current_op_own_ptr = (volatile uint8_t *) &ctx->rq_cq_ctx.cqe->op_own;
        uint8_t current_op_own = *current_op_own_ptr;

        #ifdef HOSTCQ
        __dpa_thread_outbox_fence(__DPA_R, __DPA_R);
        #else
        __dpa_thread_memory_fence(__DPA_R, __DPA_R);
        #endif

        #if CQE_COMP==1
        if (((current_op_own>>2) & 0x3) == 0x3) {
            decompress_packet(ctx);
            continue;
        }
        #elif CQE_COMP==2
        if (((current_op_own>>2) & 0x3) == 0x3) {
            __dpa_thread_window_read_inv();
            continue;
        }
        #endif

        if (likely(((current_op_own) & 0x1) != ctx->rq_cq_ctx.cq_hw_owner_bit)) {
            ctx->packets_count++;
            #ifndef RXONLY
            process_packet(ctx);
            #endif
            com_step_cq_with_one_padding(&ctx->rq_cq_ctx);

            if (ctx->packets_count - last_doorbelled_packet_count >= DOORBELL_BURST) {
                __dpa_thread_fence(__DPA_MEMORY, __DPA_W, __DPA_W);
                dbr_rq_inc_pi_value_with_one_padding(&ctx->rq_ctx, ctx->packets_count - last_doorbelled_packet_count);
                last_doorbelled_packet_count = ctx->packets_count;
            }

            if (unlikely(ctx->packets_count - last_packet_count > 10000)) {
                last_packet_count = ctx->packets_count;
                update_data_from_host_report(data_from_host, ctx);
            }
            continue;
        }


        break;
	}
    #ifdef HOSTCQ
    __dpa_thread_window_read_inv();
    #endif
    __dpa_thread_fence(__DPA_MEMORY, __DPA_W, __DPA_W);
    dbr_rq_inc_pi_value_with_one_padding(&ctx->rq_ctx, (uint32_t) (ctx->packets_count - last_doorbelled_packet_count));
    update_data_from_host_report(data_from_host, ctx);

	/* Update the memory to the chip */
    #ifdef HOSTCQ
    __dpa_thread_window_writeback();
    #endif
    __dpa_thread_memory_writeback();
	__dpa_thread_fence(__DPA_MEMORY, __DPA_W, __DPA_W);
	/* Arming cq for next packet */
	flexio_dev_cq_arm(ctx->rq_cq_ctx.cq_idx, ctx->rq_cq_ctx.cq_number);

	/* Reschedule the thread */
	flexio_dev_thread_reschedule();
}
