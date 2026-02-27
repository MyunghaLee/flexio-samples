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
	/* Packet count - used for debug message */
	uint64_t  packets_count;
	/* lkey - local memory key */
	uint32_t  lkey;
	/* Thread index - mirrors host-side assignment */
	uint32_t  thread_index;

	cq_ctx_t  rq_cq_ctx;    /* RQ CQ */
	rq_ctx_t  rq_ctx;       /* RQ */
	sq_ctx_t  sq_ctx;       /* SQ */
	cq_ctx_t  sq_cq_ctx;    /* SQ CQ */
	dt_ctx_t  dt_ctx;       /* SQ Data ring */
};

/* Static array of per-thread contexts. Each event handler is pinned to a dedicated EU,
 * so EU i only ever accesses app_ctxs[i] — no locking required.
 */
static struct app_device_ctx app_ctxs[APP_MAX_DPA_THREADS];

/* Initialize a per-thread context from the host data.
 *  ctx            - pointer to the app_device_ctx to initialize.
 *  data_from_host - pointer to host2dev_packet_processor_data from host.
 */
static void app_ctx_init(struct app_device_ctx *ctx,
			  struct host2dev_packet_processor_data *data_from_host)
{
	ctx->packets_count = 0;
	ctx->lkey = data_from_host->sq_transf.wqd_mkey_id;
	ctx->thread_index = data_from_host->thread_index;

	/* Set context for RQ's CQ */
	com_cq_ctx_init(&ctx->rq_cq_ctx,
			data_from_host->rq_cq_transf.cq_num,
			data_from_host->rq_cq_transf.log_cq_depth,
			data_from_host->rq_cq_transf.cq_ring_daddr,
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

/* process packet - read it, swap MAC addresses, modify it, create a send WQE and send it back.
 *  ctx - pointer to the per-thread app_device_ctx.
 */
static void process_packet(struct app_device_ctx *ctx)
{
	/* RX packet handling variables */
	struct flexio_dev_wqe_rcv_data_seg *rwqe;
	/* RQ WQE index */
	uint32_t rq_wqe_idx;
	/* Pointer to RQ data */
	char *rq_data;

	/* TX packet handling variables */
	union flexio_dev_sqe_seg *swqe;
	/* Pointer to SQ data */
	char *sq_data;

	/* Size of the data */
	uint32_t data_sz;

	/* Extract relevant data from the CQE */
	rq_wqe_idx = flexio_dev_cqe_get_wqe_counter(ctx->rq_cq_ctx.cqe);
	data_sz = flexio_dev_cqe_get_byte_cnt(ctx->rq_cq_ctx.cqe);

	/* Get the RQ WQE pointed to by the CQE */
	rwqe = &ctx->rq_ctx.rq_ring[rq_wqe_idx & RQ_IDX_MASK];

	/* Extract data (whole packet) pointed to by the RQ WQE */
	rq_data = flexio_dev_rwqe_get_addr(rwqe);

	/* Take the next entry from the data ring */
	sq_data = get_next_dte(&ctx->dt_ctx, DATA_IDX_MASK, LOG_WQD_CHUNK_BSIZE);

	/* Copy received packet to sq_data as is */
	memcpy(sq_data, rq_data, data_sz);

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

	/* Fill out 3-rd segment (Data) */
	swqe = get_next_sqe(&ctx->sq_ctx, SQ_IDX_MASK);
	flexio_dev_swqe_seg_mem_ptr_data_set(swqe, data_sz, ctx->lkey, (uint64_t)sq_data);

	/* Send WQE is 4 WQEBBs need to skip the 4-th segment */
	swqe = get_next_sqe(&ctx->sq_ctx, SQ_IDX_MASK);

	/* Ring DB */
	__dpa_thread_fence(__DPA_MEMORY, __DPA_W, __DPA_W);
	flexio_dev_qp_sq_ring_db(++ctx->sq_ctx.sq_pi, ctx->sq_ctx.sq_number);
	__dpa_thread_fence(__DPA_MEMORY, __DPA_W, __DPA_W);
	flexio_dev_dbr_rq_inc_pi(ctx->rq_ctx.rq_dbr);
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

	/* Poll CQ until the package is received. */
	while (flexio_dev_cqe_get_owner(ctx->rq_cq_ctx.cqe) !=
	       ctx->rq_cq_ctx.cq_hw_owner_bit) {
		/* Print the message */
		// flexio_dev_print("Process packet: %ld\n", ctx->packets_count++);
		/* Update memory to DPA */
		__dpa_thread_fence(__DPA_MEMORY, __DPA_R, __DPA_R);
		/* Process the packet */
		process_packet(ctx);
		/* Update RQ CQ */
		com_step_cq(&ctx->rq_cq_ctx);
	}
	/* Update the memory to the chip */
	__dpa_thread_fence(__DPA_MEMORY, __DPA_W, __DPA_W);
	/* Arming cq for next packet */
	flexio_dev_cq_arm(ctx->rq_cq_ctx.cq_idx, ctx->rq_cq_ctx.cq_number);

	/* Reschedule the thread */
	flexio_dev_thread_reschedule();
}
