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
	uint32_t sq_lkey;
	/* ibv lkey for RQ host data buffer; used to configure window entity 0. */
	uint32_t rq_lkey;
	/* FlexIO window ID for host memory access. */
	uint32_t window_id;
	/* Host VA base of RQ data buffer (packets land here). */
	uint64_t rqd_haddr_base;
	/* Host VA base of SQ data buffer (modified packets written here). */
	uint64_t sqd_haddr_base;
	/* DPA-accessible VA base of RQ buffer (set per handler invocation via window). */
	flexio_uintptr_t rqd_dpa_base;
	/* DPA-accessible VA base of SQ buffer (set per handler invocation via window). */
	flexio_uintptr_t sqd_dpa_base;

	cq_ctx_t rq_cq_ctx;     /* RQ CQ */
	rq_ctx_t rq_ctx;        /* RQ */
	sq_ctx_t sq_ctx;        /* SQ */
	cq_ctx_t sq_cq_ctx;     /* SQ CQ */
	dt_ctx_t dt_ctx;        /* SQ Data ring (tx_buff_idx counter only) */
} app_ctx;

/* Initialize the app_ctx structure from the host data.
 *  data_from_host - pointer host2dev_packet_processor_data from host.
 */
static void app_ctx_init(struct host2dev_packet_processor_data *data_from_host)
{
	app_ctx.packets_count = 0;

	/* ibv lkeys for host data buffers (used in WQEs and window config). */
	app_ctx.sq_lkey = data_from_host->sq_transf.wqd_mkey_id;
	app_ctx.rq_lkey = data_from_host->rq_transf.wqd_mkey_id;

	/* FlexIO window ID for host memory address translation. */
	app_ctx.window_id = data_from_host->window_id;

	/* Host VA bases of packet data buffers.
	 * wqd_daddr holds the host virtual address when buffers are in host memory.
	 */
	app_ctx.rqd_haddr_base = data_from_host->rq_transf.wqd_daddr;
	app_ctx.sqd_haddr_base = data_from_host->sq_transf.wqd_daddr;

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

	/* dt_ctx used only for tx_buff_idx counter; sq_tx_buff not dereferenced directly. */
	com_dt_ctx_init(&app_ctx.dt_ctx, data_from_host->sq_transf.wqd_daddr);
}

/* process packet - read from host RQ buffer, swap MACs, modify, send via host SQ buffer.
 *
 * Packet data lives in host memory. The DPA accesses it via FlexIO window:
 *   - Window entity 0: RQ data buffer (rq_lkey)
 *   - Window entity 1: SQ data buffer (sq_lkey)
 * Both window bases (rqd_dpa_base, sqd_dpa_base) are acquired once per handler
 * invocation in flexio_pp_dev() before this function is called.
 */
static void process_packet(void)
{
	/* RX packet handling variables */
	struct flexio_dev_wqe_rcv_data_seg *rwqe;
	/* RQ WQE index */
	uint32_t rq_wqe_idx;
	/* Host VA of received packet (from WQE addr field) */
	uint64_t rq_haddr;
	/* DPA-accessible pointer to received packet (via window entity 0) */
	char *rq_data;

	/* TX packet handling variables */
	union flexio_dev_sqe_seg *swqe;
	/* SQ TX slot index */
	uint32_t tx_idx;
	/* Host VA of SQ TX slot (placed in SQ WQE for NIC DMA-read) */
	uint64_t sq_haddr;
	/* DPA-accessible pointer to SQ TX slot (via window entity 1) */
	char *sq_data;

	/* Size of the data */
	uint32_t data_sz;

	/* Extract relevant data from the CQE */
	rq_wqe_idx = flexio_dev_cqe_get_wqe_counter(app_ctx.rq_cq_ctx.cqe);
	data_sz = flexio_dev_cqe_get_byte_cnt(app_ctx.rq_cq_ctx.cqe);

	/* Get the RQ WQE pointed to by the CQE */
	rwqe = &app_ctx.rq_ctx.rq_ring[rq_wqe_idx & RQ_IDX_MASK];

	/* WQE addr field holds the host VA of the RQ data slot.
	 * Translate to a DPA-accessible pointer using the pre-configured window base.
	 */
	rq_haddr = (uint64_t)flexio_dev_rwqe_get_addr(rwqe);
	rq_data = (char *)(app_ctx.rqd_dpa_base + (rq_haddr - app_ctx.rqd_haddr_base));

	/* Compute the next SQ TX slot (round-robin through the data ring). */
	tx_idx = app_ctx.dt_ctx.tx_buff_idx++ & DATA_IDX_MASK;
	sq_haddr = app_ctx.sqd_haddr_base + ((uint64_t)tx_idx << LOG_WQD_CHUNK_BSIZE);
	sq_data  = (char *)(app_ctx.sqd_dpa_base + ((uint64_t)tx_idx << LOG_WQD_CHUNK_BSIZE));

	/* Copy received packet into the host SQ TX buffer via window (MMIO write). */
	memcpy(sq_data, rq_data, data_sz);

	/* Swap MAC addresses. */
	swap_macs(sq_data);

	/* Primitive validation: packet is the hardcoded 65-byte test packet. */
	if (data_sz == 65) {
		/* Modify UDP payload */
		memcpy(sq_data + 0x2a, "  Event demo***************", 65 - 0x2a);
		/* Set a hex digit by index for tracing */
		sq_data[0x2a] = "0123456789abcdef"[app_ctx.dt_ctx.tx_buff_idx & 0xf];
	}

	/* Build SQ WQE (4 segments). */

	/* 1st segment: Control */
	swqe = get_next_sqe(&app_ctx.sq_ctx, SQ_IDX_MASK);
	flexio_dev_swqe_seg_ctrl_set(swqe, app_ctx.sq_ctx.sq_pi, app_ctx.sq_ctx.sq_number,
				     FLEXIO_CTRL_SEG_CE_CQE_ON_CQE_ERROR,
				     FLEXIO_CTRL_SEG_TYPE_SEND_EN);

	/* 2nd segment: Ethernet inline header */
	swqe = get_next_sqe(&app_ctx.sq_ctx, SQ_IDX_MASK);
	flexio_dev_swqe_seg_eth_set(swqe, 0, 0, 0, NULL);

	/* 3rd segment: Data pointer — uses HOST VA + ibv lkey so NIC can DMA-read. */
	swqe = get_next_sqe(&app_ctx.sq_ctx, SQ_IDX_MASK);
	flexio_dev_swqe_seg_mem_ptr_data_set(swqe, data_sz, app_ctx.sq_lkey, sq_haddr);

	/* 4th segment: padding (SQ WQE is 4 WQEBBs). */
	swqe = get_next_sqe(&app_ctx.sq_ctx, SQ_IDX_MASK);

	/* Flush writes to host SQ buffer through window before ringing the doorbell.
	 * This ensures the NIC sees the packet data when it reads the SQ WQE.
	 */
	__dpa_thread_window_writeback();

	/* Order SQ WQE write (DPA memory) relative to the doorbell write. */
	__dpa_thread_fence(__DPA_MEMORY, __DPA_W, __DPA_W);
	flexio_dev_qp_sq_ring_db(++app_ctx.sq_ctx.sq_pi, app_ctx.sq_ctx.sq_number);
	__dpa_thread_fence(__DPA_MEMORY, __DPA_W, __DPA_W);

	/* Advance RQ producer index so NIC can reuse this WQE slot. */
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
	 *
	 * Entity 0: RQ data buffer (NIC writes received packets here).
	 * Entity 1: SQ data buffer (DPA writes modified packets here for NIC TX).
	 */
	flexio_dev_window_config(FLEXIO_DEV_WINDOW_ENTITY_0,
				 (uint16_t)app_ctx.window_id, app_ctx.rq_lkey);
	flexio_dev_window_ptr_acquire(FLEXIO_DEV_WINDOW_ENTITY_0,
				      app_ctx.rqd_haddr_base, &app_ctx.rqd_dpa_base);

	flexio_dev_window_config(FLEXIO_DEV_WINDOW_ENTITY_1,
				 (uint16_t)app_ctx.window_id, app_ctx.sq_lkey);
	flexio_dev_window_ptr_acquire(FLEXIO_DEV_WINDOW_ENTITY_1,
				      app_ctx.sqd_haddr_base, &app_ctx.sqd_dpa_base);

	/* Poll CQ until all pending packets are processed. */
	while (flexio_dev_cqe_get_owner(app_ctx.rq_cq_ctx.cqe) !=
	       app_ctx.rq_cq_ctx.cq_hw_owner_bit) {
		flexio_dev_print("Process packet: %ld\n", app_ctx.packets_count++);
		/* Ensure CQE data is visible before reading packet data. */
		__dpa_thread_fence(__DPA_MEMORY, __DPA_R, __DPA_R);
		process_packet();
		com_step_cq(&app_ctx.rq_cq_ctx);
	}

	/* Ensure all DPA memory writes are visible before arming CQ. */
	__dpa_thread_fence(__DPA_MEMORY, __DPA_W, __DPA_W);
	/* Re-arm CQ to trigger on next incoming packet. */
	flexio_dev_cq_arm(app_ctx.rq_cq_ctx.cq_idx, app_ctx.rq_cq_ctx.cq_number);

	flexio_dev_thread_reschedule();
}
