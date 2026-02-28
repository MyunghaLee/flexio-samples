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

/* The structure of the sample DPA application contains global data that the application uses */
static struct {
	/* Packet count - used for debug message */
	uint64_t packets_count;
	/* ibv lkey for SQ host data buffer; placed in SQ WQE data segments. */
	uint32_t lkey;
	/* ibv lkey for RQ host data buffer; used to configure window entity 0. */
	uint32_t rq_lkey;
	/* RQ data buffer location (0=DPA memory, 1=host memory). */
	uint8_t rq_on_host;
	/* SQ data buffer location (0=DPA memory, 1=host memory). */
	uint8_t sq_on_host;
	/* FlexIO window ID for host memory access. */
	uint32_t window_id;
	/* Host VA base of RQ data buffer (packets land here). */
	flexio_uintptr_t rq_host_base;
	/* Host VA base of SQ data buffer (modified packets written here). */
	flexio_uintptr_t sq_host_base;
	/* DPA-accessible VA base of RQ buffer (set per handler invocation via window). */
	flexio_uintptr_t rq_dpa_base;
	/* DPA-accessible VA base of SQ buffer (set per handler invocation via window). */
	flexio_uintptr_t sq_dpa_base;

	cq_ctx_t rq_cq_ctx;     /* RQ CQ */
	rq_ctx_t rq_ctx;        /* RQ */
	sq_ctx_t sq_ctx;        /* SQ */
	cq_ctx_t sq_cq_ctx;     /* SQ CQ */
	dt_ctx_t dt_ctx;        /* SQ Data ring */
} app_ctx;

static inline char *rq_host_to_dpa(char *haddr)
{
	return (char *)((flexio_uintptr_t)haddr - app_ctx.rq_host_base + app_ctx.rq_dpa_base);
}

static inline char *sq_host_to_dpa(char *haddr)
{
	return (char *)((flexio_uintptr_t)haddr - app_ctx.sq_host_base + app_ctx.sq_dpa_base);
}

/* Configure window entities and map host buffer base addresses for current invocation.
 * Returns 0 on success, -1 on failure.
 */
static int map_host_buffers(void)
{
	flexio_dev_status_t ret;
	enum flexio_window_entity sq_entity = FLEXIO_DEV_WINDOW_ENTITY_0;

	if (app_ctx.rq_on_host) {
		ret = flexio_dev_window_config(FLEXIO_DEV_WINDOW_ENTITY_0,
					       (uint16_t)app_ctx.window_id, app_ctx.rq_lkey);
		if (ret != FLEXIO_DEV_STATUS_SUCCESS)
			return -1;
		ret = flexio_dev_window_ptr_acquire(FLEXIO_DEV_WINDOW_ENTITY_0,
						    (uint64_t)app_ctx.rq_host_base,
						    &app_ctx.rq_dpa_base);
		if (ret != FLEXIO_DEV_STATUS_SUCCESS)
			return -1;
		sq_entity = FLEXIO_DEV_WINDOW_ENTITY_1;
	}

	if (app_ctx.sq_on_host) {
		ret = flexio_dev_window_config(sq_entity,
					       (uint16_t)app_ctx.window_id, app_ctx.lkey);
		if (ret != FLEXIO_DEV_STATUS_SUCCESS)
			return -1;
		ret = flexio_dev_window_ptr_acquire(sq_entity,
						    (uint64_t)app_ctx.sq_host_base,
						    &app_ctx.sq_dpa_base);
		if (ret != FLEXIO_DEV_STATUS_SUCCESS)
			return -1;
	}

	return 0;
}

/* Initialize the app_ctx structure from the host data.
 *  data_from_host - pointer host2dev_packet_processor_data from host.
 */
static void app_ctx_init(struct host2dev_packet_processor_data *data_from_host)
{
	app_ctx.packets_count = 0;

	/* ibv lkeys for host data buffers (used in WQEs and window config). */
	app_ctx.lkey = data_from_host->sq_transf.wqd_mkey_id;
	app_ctx.rq_lkey = data_from_host->rq_transf.wqd_mkey_id;

	/* Data buffer locations. */
	app_ctx.rq_on_host = data_from_host->rq_transf.daddr_on_host;
	app_ctx.sq_on_host = data_from_host->sq_transf.daddr_on_host;

	/* FlexIO window ID for host memory address translation. */
	app_ctx.window_id = data_from_host->window_id;

	/* Buffer base addresses.
	 * When on host: wqd_daddr holds the host virtual address.
	 * When on DPA: wqd_daddr holds the DPA heap address.
	 */
	app_ctx.rq_host_base = data_from_host->rq_transf.wqd_daddr;
	app_ctx.sq_host_base = data_from_host->sq_transf.wqd_daddr;
	/* Initialize DPA bases to match host bases; overwritten by map_host_buffers()
	 * when buffers are on host.
	 */
	app_ctx.rq_dpa_base = app_ctx.rq_host_base;
	app_ctx.sq_dpa_base = app_ctx.sq_host_base;

	/* Set context for RQ's CQ */
	com_cq_ctx_init(&app_ctx.rq_cq_ctx,
			data_from_host->rq_cq_transf.cq_num,
			data_from_host->rq_cq_transf.log_cq_depth,
			data_from_host->rq_cq_transf.cq_ring_daddr,
			data_from_host->rq_cq_transf.cq_dbr_daddr);

	/* Set context for RQ */
	com_rq_ctx_init(&app_ctx.rq_ctx,
			data_from_host->rq_transf.wq_num,
			data_from_host->rq_transf.wq_ring_daddr,
			data_from_host->rq_transf.wq_dbr_daddr);

	/* Set context for SQ */
	com_sq_ctx_init(&app_ctx.sq_ctx,
			data_from_host->sq_transf.wq_num,
			data_from_host->sq_transf.wq_ring_daddr);

	/* Set context for SQ's CQ */
	com_cq_ctx_init(&app_ctx.sq_cq_ctx,
			data_from_host->sq_cq_transf.cq_num,
			data_from_host->sq_cq_transf.log_cq_depth,
			data_from_host->sq_cq_transf.cq_ring_daddr,
			data_from_host->sq_cq_transf.cq_dbr_daddr);

	/* Set context for data */
	com_dt_ctx_init(&app_ctx.dt_ctx, data_from_host->sq_transf.wqd_daddr);
}

/* process packet - read it, swap MAC addresses, modify it, create a send WQE and send it back.
 *
 * Packet data lives in host memory. The DPA accesses it via FlexIO window:
 *   - Window entity 0: RQ data buffer (rq_lkey)
 *   - Window entity 1: SQ data buffer (lkey)
 * Both window bases (rq_dpa_base, sq_dpa_base) are acquired once per handler
 * invocation in flexio_pp_dev() before this function is called.
 */
static void process_packet(void)
{
	/* RX packet handling variables */
	struct flexio_dev_wqe_rcv_data_seg *rwqe;
	/* RQ WQE index */
	uint32_t rq_wqe_idx;
	/* Pointer to RQ data */
	char *rq_data;
	/* Mapped pointer to RQ data when backing memory is on host. */
	char *rq_data_dpa;

	/* TX packet handling variables */
	union flexio_dev_sqe_seg *swqe;
	/* Pointer stored in SQ data ring (host VA in host-memory mode). */
	char *sq_data;
	/* Mapped pointer to SQ data when backing memory is on host. */
	char *sq_data_dpa;

	/* Size of the data */
	uint32_t data_sz;

	/* Extract relevant data from the CQE */
	rq_wqe_idx = flexio_dev_cqe_get_wqe_counter(app_ctx.rq_cq_ctx.cqe);
	data_sz = flexio_dev_cqe_get_byte_cnt(app_ctx.rq_cq_ctx.cqe);

	/* Get the RQ WQE pointed to by the CQE */
	rwqe = &app_ctx.rq_ctx.rq_ring[rq_wqe_idx & RQ_IDX_MASK];

	/* Extract data (whole packet) pointed to by the RQ WQE */
	rq_data = flexio_dev_rwqe_get_addr(rwqe);
	rq_data_dpa = app_ctx.rq_on_host ? rq_host_to_dpa(rq_data) : rq_data;

	/* Take the next entry from the data ring */
	sq_data = get_next_dte(&app_ctx.dt_ctx, DATA_IDX_MASK, LOG_WQD_CHUNK_BSIZE);
	sq_data_dpa = app_ctx.sq_on_host ? sq_host_to_dpa(sq_data) : sq_data;

	/* Copy received packet to sq_data as is */
	memcpy(sq_data_dpa, rq_data_dpa, data_sz);

	/* swap mac address */
	swap_macs(sq_data_dpa);

	/* Primitive validation, that packet is our hardcoded */
	if (data_sz == 65) {
		/* modify UDP payload */
		memcpy(sq_data_dpa + 0x2a, "  Event demo***************", 65 - 0x2a);

		/* Set hexadecimal value by the index */
		sq_data_dpa[0x2a] = "0123456789abcdef"[app_ctx.dt_ctx.tx_buff_idx & 0xf];
	}

	/* Take first segment for SQ WQE (3 segments will be used) */
	swqe = get_next_sqe(&app_ctx.sq_ctx, SQ_IDX_MASK);

	/* Fill out 1-st segment (Control) */
	flexio_dev_swqe_seg_ctrl_set(swqe, app_ctx.sq_ctx.sq_pi, app_ctx.sq_ctx.sq_number,
				     FLEXIO_CTRL_SEG_CE_CQE_ON_CQE_ERROR,
				     FLEXIO_CTRL_SEG_TYPE_SEND_EN);

	/* Fill out 2-nd segment (Ethernet) */
	swqe = get_next_sqe(&app_ctx.sq_ctx, SQ_IDX_MASK);
	flexio_dev_swqe_seg_eth_set(swqe, 0, 0, 0, NULL);

	/* Fill out 3-rd segment (Data) */
	swqe = get_next_sqe(&app_ctx.sq_ctx, SQ_IDX_MASK);
	flexio_dev_swqe_seg_mem_ptr_data_set(swqe, data_sz, app_ctx.lkey, (uint64_t)sq_data);

	/* Send WQE is 4 WQEBBs need to skip the 4-th segment */
	swqe = get_next_sqe(&app_ctx.sq_ctx, SQ_IDX_MASK);

	/* Ring DB */
	if (app_ctx.sq_on_host)
		__dpa_thread_window_writeback();
	__dpa_thread_fence(__DPA_MEMORY, __DPA_W, __DPA_W);
	flexio_dev_qp_sq_ring_db(++app_ctx.sq_ctx.sq_pi, app_ctx.sq_ctx.sq_number);
	__dpa_thread_fence(__DPA_MEMORY, __DPA_W, __DPA_W);
	flexio_dev_dbr_rq_inc_pi(app_ctx.rq_ctx.rq_dbr);
}

/* Entry point function that host side call for the execute.
 *  thread_arg - pointer to the host2dev_packet_processor_data structure
 *     to transfer data from the host side.
 */
flexio_dev_event_handler_t flexio_pp_dev;
__dpa_global__ void flexio_pp_dev(uint64_t thread_arg)
{
	struct host2dev_packet_processor_data *data_from_host = (void *)thread_arg;

	/* Initialize context on first invocation. */
	if (!data_from_host->not_first_run) {
		app_ctx_init(data_from_host);
		data_from_host->not_first_run = 1;
	}

	/* Configure FlexIO window entities for host memory access.
	 *
	 * The window mkey must be (re-)configured on every handler invocation
	 * because the thread context window state resets between invocations.
	 */
	if (app_ctx.rq_on_host || app_ctx.sq_on_host) {
		if (map_host_buffers()) {
			flexio_dev_thread_reschedule();
			return;
		}
	}

	/* Poll CQ until all pending packets are processed. */
	while (flexio_dev_cqe_get_owner(app_ctx.rq_cq_ctx.cqe) !=
	       app_ctx.rq_cq_ctx.cq_hw_owner_bit) {
		/* Ensure CQE data is visible before reading packet data. */
		__dpa_thread_fence(__DPA_MEMORY, __DPA_R, __DPA_R);
		/* Process the packet. */
		process_packet();
		app_ctx.packets_count++;
		/* Update RQ CQ */
		com_step_cq(&app_ctx.rq_cq_ctx);
	}

	/* Ensure all DPA memory writes are visible before arming CQ. */
	__dpa_thread_fence(__DPA_MEMORY, __DPA_W, __DPA_W);
	/* Re-arm CQ to trigger on next incoming packet. */
	flexio_dev_cq_arm(app_ctx.rq_cq_ctx.cq_idx, app_ctx.rq_cq_ctx.cq_number);

	flexio_dev_thread_reschedule();
}
