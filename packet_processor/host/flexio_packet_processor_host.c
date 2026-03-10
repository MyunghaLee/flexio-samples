#define _GNU_SOURCE
#include <stdatomic.h>
#include <arm_neon.h>
#include <sched.h>
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
/* Source file for host part of packet processing sample.
 * Contain functions for parsing input parameters, allocating and freeing resources,
 * initialization of a process and a event handler, and running event handler.
 */

/* Used for geteuid and sleep functions. */
#include <unistd.h>

/* Used for SIGINT signal handling in the prompt loop. */
#include <signal.h>

/* Used for strtoul and other stdlib functions. */
#include <stdlib.h>

/* Used for memcpy/memset/memcmp/strcmp. */
#include <string.h>

/* Used for host (x86/DPU) memory allocations. */
#include <malloc.h>

/* Used for host-side observer pthread. */
#include <pthread.h>

/* Used for htobe16/be16toh in host CQE decompression. */
#include <endian.h>

/* Used for clock_gettime in latency stats. */
#include <time.h>

/* Used for IBV device operations. */
#include <infiniband/mlx5dv.h>

/* Flex IO SDK host side version API header. */
#include <libflexio/flexio_ver.h>

/* Set current version of FLEXIO_VER_USED. */
#define FLEXIO_VER_USED FLEXIO_VER(25, 10, 0)

/* Flex IO SDK host side API header. */
#include <libflexio/flexio.h>

// #include <immintrin.h>

/* Flow steering utilities helper header. */
#include "flow_steering_utils.h"

/* Common header for communication between host and DPA. */
#include "../flexio_packet_processor_com.h"

/* Flex IO packet processor device (DPA) side function stub. */
extern flexio_func_t flexio_pp_dev;

/* Per-thread resources: one event handler, one SQ/RQ pair, one set of steering rules. */
struct thread_ctx {
	/* Transfer descriptors */
	struct app_transfer_cq sq_cq_transf;
	struct app_transfer_wq sq_transf;
	struct app_transfer_cq rq_cq_transf;
	struct app_transfer_wq rq_transf;

	/* Host buffer resources (used only when hostbuf_enable == 1).
	 * Combined buffer layout:
	 *   [RQ data (Q_DATA_BSIZE) | SQ data (Q_DATA_BSIZE) | RQ CQ ring (CQ_BSIZE, if hostcq)]
	 * A single ibv_reg_mr covers the whole region so all parts share one lkey,
	 * allowing the DPA to access all via a single FlexIO window entity (ENTITY_0).
	 */
	void          *data_hbuf; /* combined host buffer */
	struct ibv_mr *data_mr;   /* single MR covering the combined buffer */ //until here, 128B

	/* DEVX UMEM registration for the RQ CQ ring portion of the combined buffer.
	 * Needed for flexio_cq_create with FLEXIO_MEMTYPE_HOST qmem (hostcq mode only).
	 */
	struct mlx5dv_devx_umem *rq_cq_ring_umem;

	/* Event handler */
	struct flexio_event_handler *pp_eh;

	/* SQ resources */
	struct flexio_cq   *flexio_sq_cq_ptr;
	struct flexio_sq   *flexio_sq_ptr;
	struct flexio_mkey *sqd_mkey;

	/* RQ resources */
	struct flexio_cq   *flexio_rq_cq_ptr;
	struct flexio_rq   *flexio_rq_ptr;
	struct flexio_mkey *rqd_mkey; // 256B

	/* Flow steering (per-thread matcher + rule) */
	struct flow_matcher *rx_matcher;
	struct flow_rule    *rx_rule;
	struct flow_matcher *tx_matcher;      /* NULL in nic_mode */
	struct flow_rule    *tx_rule_table;   /* NULL in nic_mode */
	struct flow_rule    *tx_rule_vport;   /* NULL in nic_mode */

	/* DPA heap address of this thread's host2dev descriptor */
	flexio_uintptr_t app_data_daddr;

	uint32_t thread_index;
    uint8_t rsvd[12];
}  __attribute__((__packed__, aligned(64))) ;

/* Application context struct holding necessary host side variables. */
struct app_context {
	/* Flex IO process is used to load a program to the DPA. */
	struct flexio_process *flexio_process;
	/* Flex IO application to load to the process. */
	struct flexio_app *flexio_app;
	/* Flex IO message stream is used to get messages from the DPA. */
	struct flexio_msg_stream *stream;
	/* DPA user access register (DPA UAR) for all application's queues.
	 * Will be set to the Flex IO process UAR.
	 */
	struct flexio_uar *process_uar;
	/* Protection domain (PD) for all application's queues.
	 * Will be set to the Flex IO process PD.
	 */
	struct ibv_pd *process_pd;
	/* IBV context opened for the device name provided by the user. */
	struct ibv_context *ibv_ctx;

	/* Number of DPA threads to create. */
	int num_threads;
	/* Per-thread context array (calloc'd, size = num_threads). */
	struct thread_ctx *threads;
	/* FlexIO window for DPA→host memory access (created when --hostbuf on). */
	struct flexio_window *window;

    struct hostdecomp_ctx *decomp_ctx;
};

/* Host-side 64B CQE layout used by the hostdecomp observer. */
struct host_cqe64 {
	uint32_t rsvd00[5];
	uint16_t csum_ok;
	uint8_t  rsvd22[2];
	uint32_t rsvd24[2];
	uint32_t srqn_uidx;
	uint32_t imm_inval_pkey;
	uint32_t rsvd40;
	uint32_t byte_cnt;
	uint32_t rsvd48;
	uint8_t  hw_err_syndrome;
	uint8_t  rsvd50;
	uint8_t  vendor_err_synd;
	uint8_t  syndrome;
	union {
		struct {
			uint8_t sop_rdrop;
			uint8_t qpn24[3];
		};
		uint32_t qpn;
	};
	uint16_t wqe_counter;
	union {
		uint8_t signature;
		uint8_t validity_iteration_count;
	};
	uint8_t op_own;
} __attribute__((__packed__, aligned(8)));

/* Mini CQE block overlay (64B compressed CQE block). */
struct host_mini_cqe64 {
	uint64_t mini_cqe[7];
	uint8_t  rsvd0[6];
	uint8_t  validity_iteration_count;
	uint8_t  num_and_type;
} __attribute__((__packed__, aligned(8)));

/* Per-DPA-thread state for the host decompression observer. */
struct hostdecomp_queue_ctx {
	struct host_cqe64 *cq_ring_addr; /* pointer to the CQ ring which is on DPA mem */
    struct hostdecomp_thread_memo *dpa_memo;
    struct hostdecomp_thread_memo *cpu_memo;
	uint32_t thread_index;
	uint32_t cq_idx;
	uint32_t log_cq_depth;
    uint8_t  cq_hw_owner_bit;
    uint8_t  rsvd[3];
	uint64_t decomp_total_ns;
	uint64_t decomp_total_mini;
	uint64_t decomp_last_report_mini;
}__attribute__((__packed__, aligned(64)));

/* Single host observer that rotates across all DPA threads' CQ rings. */
struct hostdecomp_ctx {
	struct hostdecomp_queue_ctx *queues;
	uint32_t num_queues;
	uint32_t next_queue_idx;
	pthread_t thread;
	int thread_started;
	volatile int stop;
    uint8_t rsvd[32];
}__attribute__((__packed__, aligned(64)));

/* Open ibv device
 * Returns 0 on success and -1 if the destroy was failed.
 * app_ctx - app_ctx - pointer to app_context structure.
 * device - device name to open.
 */
static int app_open_ibv_ctx(struct app_context *app_ctx, char *device)
{
	/* Queried IBV device list. */
	struct ibv_device **dev_list;
	/* Function return value. */
	int ret = 0;
	/* IBV device iterator. */
	int dev_i;

	/* Query IBV devices list. */
	dev_list = ibv_get_device_list(NULL);
	if (!dev_list) {
		printf("Failed to get IB devices list\n");
		return -1;
	}

	/* Loop over found IBV devices. */
	for (dev_i = 0; dev_list[dev_i]; dev_i++) {
		/* Look for a device with the user provided name. */
		if (!strcmp(ibv_get_device_name(dev_list[dev_i]), device))
			break;
	}

	/* Check a device was found. */
	if (!dev_list[dev_i]) {
		printf("No IBV device found for device name '%s'\n", device);
		ret = -1;
		goto cleanup;
	}

	/* Open IBV device context for the requested device. */
	app_ctx->ibv_ctx = ibv_open_device(dev_list[dev_i]);
	if (!app_ctx->ibv_ctx) {
		printf("Couldn't open an IBV context for device '%s'\n", device);
		ret = -1;
	}

cleanup:
	/* Free queried IBV devices list. */
	ibv_free_device_list(dev_list);

	return ret;
}

/* Convert logarithm to value. */
#define L2V(l) (1UL << (l))
/* Number of entries in each RQ/SQ/CQ is 2^LOG_Q_DEPTH. */
#define LOG_Q_DEPTH LOG_QUEUE_SIZE
#define Q_DEPTH L2V(LOG_Q_DEPTH)
/* SQ/RQ data entry byte size is 512B (enough for packet data in this case). */
#define LOG_Q_DATA_ENTRY_BSIZE 11
/* SQ/RQ data entry byte size log to value. */
#define Q_DATA_ENTRY_BSIZE L2V(LOG_Q_DATA_ENTRY_BSIZE)
/* SQ/RQ DATA byte size is queue depth times entry byte size. */
#define Q_DATA_BSIZE Q_DEPTH *Q_DATA_ENTRY_BSIZE

#ifndef HOSTBUF
/* Creates an MKey with proper permissions for access from DPA.
 * For this application, we only need memory write access.
 * Returns pointer to flexio_mkey structure on success. Otherwise, returns NULL.
 * app_ctx - pointer to app_context structure.
 * daddr - address of MKEY data.
 */
static struct flexio_mkey *create_dpa_mkey(struct app_context *app_ctx, flexio_uintptr_t daddr)
{
	/* Flex IO MKey attributes. */
	struct flexio_mkey_attr mkey_attr = {0};
	/* Flex IO MKey. */
	struct flexio_mkey *mkey;

	/* Set MKey protection domain (PD) to the Flex IO process PD. */
	mkey_attr.pd = app_ctx->process_pd;
	/* Set MKey address. */
	mkey_attr.daddr = daddr;
	/* Set MKey length. */
	mkey_attr.len = Q_DATA_BSIZE;
	/* Set MKey access to memory write (from DPA). */
	mkey_attr.access = IBV_ACCESS_LOCAL_WRITE;
	/* Create Flex IO MKey. */
	if (flexio_device_mkey_create(app_ctx->flexio_process, &mkey_attr, &mkey)) {
		printf("Failed to create Flex IO Mkey\n");
		return NULL;
	}

	return mkey;
}
#endif

/* Base source MAC address; thread n matches SMAC = BASE_SMAC + n. */
#define BASE_SMAC 0x02427e7feb02ULL
// #define BASE_SMAC 0xe8ebd3a72f16ULL
#define THREAD_SMAC(i) (BASE_SMAC + (i))

/* Creates steering rules for a single thread.
 * Returns 0 on success and -1 if the allocation was failed.
 * app_ctx  - pointer to app_context structure.
 * t        - pointer to thread_ctx structure for this thread.
 * nic_mode - if set to 1, the sample runs on ConnectX part.
 */
static int create_thread_steering_rules(struct app_context *app_ctx,
					struct thread_ctx *t, int nic_mode)
{
	uint64_t smac = THREAD_SMAC(t->thread_index);

	/* Create RX flow matcher. */
	t->rx_matcher = create_matcher_rx(app_ctx->ibv_ctx);
	if (!t->rx_matcher) {
		printf("Failed to create RX matcher\n");
		return -1;
	}

	/* Create RX flow rule for the specific source MAC of incoming packets. */
	t->rx_rule = create_rule_rx_mac_match(t->rx_matcher,
					      flexio_rq_get_tir(t->flexio_rq_ptr), smac);
	if (!t->rx_rule) {
		printf("Failed to create RX steering rule\n");
		return -1;
	}

	/* If the sample runs on NIC, the outgoing rule is already configured.
	 * If the sample runs on DPU, the outgoing rule is configured as a DROP rule,
	 * so the sample needs to reconfigure the outgoing rule.
	 */
	if (!nic_mode) {
		/* Add a rule to steer outgoing traffic to the vport for it to exit from
		 * the DPU to the wire.
		 */
		/* Create TX flow matcher. */
		t->tx_matcher = create_matcher_tx(app_ctx->ibv_ctx);
		if (!t->tx_matcher) {
			printf("Failed to create TX matcher\n");
			return -1;
		}

		/* Create a TX flow rule to forward outgoing packets to SW steering table. */
		t->tx_rule_table = create_rule_tx_fwd_to_sws_table(t->tx_matcher, smac);
		if (!t->tx_rule_table) {
			printf("Failed to create TX table steering rule\n");
			return -1;
		}

		/* Create a TX flow rule to forward outgoing packets to vport (wire). */
		t->tx_rule_vport = create_rule_tx_fwd_to_vport(t->tx_matcher, smac);
		if (!t->tx_rule_vport) {
			printf("Failed to create TX vport steering rule\n");
			return -1;
		}
	}

	return 0;
}

/* CQE size is 64B. */
#define CQE_BSIZE 64
#define CQ_BSIZE (Q_DEPTH * CQE_BSIZE)
/* Allocate and initialize DPA heap memory for CQ.
 * Returns 0 on success and -1 if the allocation fails.
 * process - pointer to the previously allocated process information.
 * cq_transf - structure with allocated DPA buffers for CQ.
 */
static int cq_mem_alloc(struct flexio_process *process, struct app_transfer_cq *cq_transf)
{
	/* Pointer to the CQ ring source memory on the host (to copy). */
	struct mlx5_cqe64 *cq_ring_src;
	/* Temp pointer to an iterator for CQE initialization. */
	struct mlx5_cqe64 *cqe;

	/* DBR source memory on the host (to copy). */
	__be32 dbr[2] = { 0, 0 };
	/* Function return value. */
	int ret = 0;
	/* Iterator for CQE initialization. */
	uint32_t i;

	/* Allocate and initialize CQ DBR memory on the DPA heap memory. */
	if (flexio_copy_from_host(process, dbr, sizeof(dbr), &cq_transf->cq_dbr_daddr)) {
		printf("Failed to allocate CQ DBR memory on DPA heap.\n");
		return -1;
	}

	/* Allocate memory for the CQ ring on the host. */
	cq_ring_src = calloc(Q_DEPTH, CQE_BSIZE);
	if (!cq_ring_src) {
		printf("Failed to allocate memory for cq_ring_src.\n");
		return -1;
	}

	/* Init CQEs and set ownership bit. */
	for (i = 0, cqe = cq_ring_src; i < Q_DEPTH; i++)
		mlx5dv_set_cqe_owner(cqe++, 1);

	/* Allocate and copy the initialized CQ ring from host to DPA heap memory. */
	if (flexio_copy_from_host(process, cq_ring_src, CQ_BSIZE, &cq_transf->cq_ring_daddr)) {
		printf("Failed to allocate CQ ring memory on DPA heap.\n");
		ret = -1;
	}

	/* Free CQ ring source memory from host once copied to DPA. */
	free(cq_ring_src);

	return ret;
}

#ifdef HOSTCQ
/* Allocate RQ CQ memory with ring in host memory (within combined data buffer, hostcq mode).
 * The combined buffer must have been allocated by sq_mem_alloc_hostbuf before this call.
 * Only allocates CQ DBR on DPA heap; the ring resides at data_hbuf + 2*Q_DATA_BSIZE.
 * Registers a DEVX UMEM for the ring so flexio_cq_create can use FLEXIO_MEMTYPE_HOST.
 * Returns 0 on success and -1 on failure.
 * app_ctx - pointer to app_context structure.
 * t       - pointer to thread_ctx for this thread.
 */
static int rq_cq_mem_alloc_host(struct app_context *app_ctx, struct thread_ctx *t)
{
	struct flexio_process *process = app_ctx->flexio_process;
	__be32 dbr[2] = { 0, 0 };
	struct mlx5_cqe64 *cqe_p;
	void *cq_ring_ptr;
	uint32_t i;

	if (!t->data_hbuf) {
		printf("rq_cq_mem_alloc_host: combined buffer not allocated\n");
		return -1;
	}

	/* Allocate CQ DBR on DPA heap (DPA increments consumer index directly). */
	if (flexio_copy_from_host(process, dbr, sizeof(dbr),
				  &t->rq_cq_transf.cq_dbr_daddr)) {
		printf("Failed to allocate RQ CQ DBR on DPA heap.\n");
		return -1;
	}

	/* CQ ring occupies the third region of the combined buffer. */
	cq_ring_ptr = (char *)t->data_hbuf + 2 * Q_DATA_BSIZE;

	/* Initialize CQEs: zero-fill then set owner bit = 1 (HW-owned initial state). */
	memset(cq_ring_ptr, 0, CQ_BSIZE);
	for (i = 0, cqe_p = (struct mlx5_cqe64 *)cq_ring_ptr; i < Q_DEPTH; i++)
		mlx5dv_set_cqe_owner(cqe_p++, 1);

	/* Register a DEVX UMEM covering just the CQ ring portion.
	 * humem_offset = 0 because this UMEM starts at the CQ ring start address.
	 */
	t->rq_cq_ring_umem = mlx5dv_devx_umem_reg(app_ctx->ibv_ctx, cq_ring_ptr, CQ_BSIZE,
						   IBV_ACCESS_LOCAL_WRITE);
	if (!t->rq_cq_ring_umem) {
		printf("Failed to register DEVX UMEM for host RQ CQ ring.\n");
		flexio_buf_dev_free(process, t->rq_cq_transf.cq_dbr_daddr);
		t->rq_cq_transf.cq_dbr_daddr = 0;
		return -1;
	}

	/* cq_ring_daddr = 0: host VA is passed to DPA in copy_thread_data_to_dpa. */
	t->rq_cq_transf.cq_ring_daddr = 0;
	return 0;
}
#endif

/* SQ WQE byte size is 64B. */
#define LOG_SQ_WQE_BSIZE 6
/* SQ WQE byte size log to value. */
#define SQ_WQE_BSIZE L2V(LOG_SQ_WQE_BSIZE)
/* SQ ring byte size is queue depth times WQE byte size. */
#define SQ_RING_BSIZE (Q_DEPTH * SQ_WQE_BSIZE)
#ifndef HOSTBUF
/* Allocate DPA heap memory for SQ.
 * Returns 0 on success and -1 if the allocation fails.
 * process - pointer to the previously allocated process info.
 * sq_transf - structure with allocated DPA buffers for SQ.
 */
static int sq_mem_alloc(struct flexio_process *process, struct app_transfer_wq *sq_transf)
{
	/* Allocate DPA heap memory for SQ data. */
	flexio_buf_dev_alloc(process, Q_DATA_BSIZE, &sq_transf->wqd_daddr);
	if (!sq_transf->wqd_daddr)
		return -1;

	/* Allocate DPA heap memory for SQ ring. */
	flexio_buf_dev_alloc(process, SQ_RING_BSIZE, &sq_transf->wq_ring_daddr);
	if (!sq_transf->wq_ring_daddr)
		return -1;

	return 0;
}
#endif

#ifdef HOSTBUF
/* Allocate host memory and register a single MR for both RQ and SQ data buffers (hostbuf mode).
 * The combined buffer layout: [RQ data | SQ data], each Q_DATA_BSIZE bytes.
 * One ibv lkey covers both halves, so only FLEXIO_DEV_WINDOW_ENTITY_0 is needed on the DPA.
 * sq_transf->wqd_daddr/wqd_mkey_id are set here; rq_transf fields are set by rq_mem_alloc_hostbuf.
 * Returns 0 on success and -1 on failure.
 * app_ctx  - pointer to app_context structure.
 * t        - pointer to thread_ctx for this thread.
 * sq_transf - SQ transfer struct to populate.
 */
static int sq_mem_alloc_hostbuf(struct app_context *app_ctx, struct thread_ctx *t,
				struct app_transfer_wq *sq_transf)
{
	/* When hostcq is also enabled, append a CQ ring after RQ+SQ data.
	 * Layout: [RQ data (Q_DATA_BSIZE) | SQ data (Q_DATA_BSIZE) | CQ ring (CQ_BSIZE)]
	 * A single ibv_reg_mr covers all three regions under one lkey.
	 */
    #ifdef HOSTCQ
    #if CQE_COMP==2
	size_t hbuf_size = 2 * Q_DATA_BSIZE + CQ_BSIZE + 2 * sizeof(struct hostdecomp_thread_memo);
    #else
	size_t hbuf_size = 2 * Q_DATA_BSIZE + CQ_BSIZE;
    #endif
    #else
	size_t hbuf_size = 2 * Q_DATA_BSIZE;
    #endif

	if (posix_memalign(&t->data_hbuf, CQ_BSIZE, hbuf_size)) {
		printf("Failed to allocate host memory for combined data buffer\n");
		return -1;
	}
	memset(t->data_hbuf, 0, hbuf_size);

	/* Register a single MR covering the combined buffer.
	 * NIC needs REMOTE_WRITE to DMA packets into the RQ half and REMOTE_READ to
	 * fetch packet data from the SQ half. LOCAL_WRITE is required by the verbs API.
	 */
	t->data_mr = ibv_reg_mr(app_ctx->process_pd, t->data_hbuf, hbuf_size,
			       IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE |
			       IBV_ACCESS_REMOTE_READ);
	if (!t->data_mr) {
		printf("Failed to register MR for combined data host buffer\n");
		free(t->data_hbuf);
		t->data_hbuf = NULL;
		return -1;
	}

	/* SQ occupies the second half of the combined buffer. */
	sq_transf->wqd_daddr = (flexio_uintptr_t)((uintptr_t)t->data_hbuf + Q_DATA_BSIZE);
	sq_transf->wqd_mkey_id = t->data_mr->lkey;

	/* Allocate DPA heap memory for SQ ring (descriptor ring stays on DPA). */
	flexio_buf_dev_alloc(app_ctx->flexio_process, SQ_RING_BSIZE, &sq_transf->wq_ring_daddr);
	if (!sq_transf->wq_ring_daddr)
		return -1;

	return 0;
}
#endif

/* Create an SQ over the DPA for sending packets from DPA to wire.
 * A CQ is also created for the SQ.
 * Returns 0 on success and -1 if the allocation fails.
 * app_ctx - pointer to app_context structure.
 * t       - pointer to thread_ctx for this thread.
 */
static int create_thread_sq(struct app_context *app_ctx, struct thread_ctx *t)
{
	/* Pointer to the application Flex IO process (ease of use). */
	struct flexio_process *app_fp = app_ctx->flexio_process;
	/* Attributes for the SQ's CQ. */
	struct flexio_cq_attr sqcq_attr = {0};
	/* Attributes for the SQ. */
	struct flexio_wq_attr sq_attr = {0};

	/* UAR ID for CQ/SQ from Flex IO process UAR. */
	uint32_t uar_id = flexio_uar_get_id(app_ctx->process_uar);
	/* SQ's CQ number. */
	uint32_t cq_num;

	/* Allocate CQ memory (ring and DBR) on DPA heap memory. */
	if (cq_mem_alloc(app_fp, &t->sq_cq_transf)) {
		printf("Failed to alloc memory for SQ's CQ.\n");
		return -1;
	}

	/* Set CQ depth (log) attribute. */
	sqcq_attr.log_cq_depth = LOG_Q_DEPTH;
	/* Set CQ element type attribute to 'non DPA CQ'.
	 * This means this CQ will not be attached to an event handler.
	 */
	sqcq_attr.element_type = FLEXIO_CQ_ELEMENT_TYPE_NON_DPA_CQ;
	/* Set CQ UAR ID attribute to the Flex IO process UAR ID.
	 * This will allow updating/arming the CQ from the DPA side.
	 */
	sqcq_attr.uar_id = uar_id;
	/* Set CQ DBR memory. DBR memory is on the DPA side in order to allow direct access from
	 * DPA.
	 */
	sqcq_attr.cq_dbr_daddr = t->sq_cq_transf.cq_dbr_daddr;
	/* Set CQ ring memory. Ring memory is on the DPA side in order to allow reading CQEs from
	 * DPA during packet forwarding.
	 */
	sqcq_attr.cq_ring_qmem.daddr = t->sq_cq_transf.cq_ring_daddr;
	/* Create CQ for SQ. */
	if (flexio_cq_create(app_fp, NULL, &sqcq_attr, &t->flexio_sq_cq_ptr)) {
		printf("Failed to create Flex IO CQ\n");
		return -1;
	}

	/* Fetch SQ's CQ number to communicate to DPA side. */
	cq_num = flexio_cq_get_cq_num(t->flexio_sq_cq_ptr);
	/* Set SQ's CQ number in communication struct. */
	t->sq_cq_transf.cq_num = cq_num;
	/* Set SQ's CQ depth in communication struct. */
	t->sq_cq_transf.log_cq_depth = LOG_Q_DEPTH;
	/* Allocate SQ memory (ring and data). Data goes to host or DPA depending on mode. */
    #ifdef HOSTBUF
	if (sq_mem_alloc_hostbuf(app_ctx, t, &t->sq_transf))
    #else
	if (sq_mem_alloc(app_fp, &t->sq_transf))
    #endif
    {
		printf("Failed to allocate memory for SQ\n");
		return -1;
	}

	/* Set SQ depth (log) attribute. */
	sq_attr.log_wq_depth = LOG_Q_DEPTH;
	/* Set SQ UAR ID attribute to the Flex IO process UAR ID.
	 * This will allow writing doorbells to the SQ from the DPA side.
	 */
	sq_attr.uar_id = uar_id;
	/* Set SQ ring memory. Ring memory is on the DPA side in order to allow writing WQEs from
	 * DPA during packet forwarding.
	 */
	sq_attr.wq_ring_qmem.daddr = t->sq_transf.wq_ring_daddr;

	/* Set SQ protection domain */
	sq_attr.pd = app_ctx->process_pd;

	/* Create SQ.
	 * Second argument is NULL as SQ is created on the same GVMI as the process.
	 */
	if (flexio_sq_create(app_fp, NULL, cq_num, &sq_attr, &t->flexio_sq_ptr)) {
		printf("Failed to create Flex IO SQ\n");
		return -1;
	}

	/* Fetch SQ's number to communicate to DPA side. */
	t->sq_transf.wq_num = flexio_sq_get_wq_num(t->flexio_sq_ptr);

    #ifndef HOSTBUF
	/* Create an MKey for SQ data buffer (DPA mode only; hostbuf uses ibv lkey from MR). */
    t->sqd_mkey = create_dpa_mkey(app_ctx, t->sq_transf.wqd_daddr);
    if (!t->sqd_mkey) {
        printf("Failed to create an MKey for SQ data buffer\n");
        return -1;
    }
    t->sq_transf.wqd_mkey_id = flexio_mkey_get_id(t->sqd_mkey);
    #endif

	return 0;
}

/* RQ WQE byte size is 64B. */
#define LOG_RQ_WQE_BSIZE 6
/* RQ WQE byte size log to value. */
#define RQ_WQE_BSIZE L2V(LOG_RQ_WQE_BSIZE)
/* RQ ring byte size is queue depth times WQE byte size. */
#define RQ_RING_BSIZE (Q_DEPTH * RQ_WQE_BSIZE)
#ifndef HOSTBUF
/* Allocate DPA heap memory for SQ.
 * Returns 0 on success and -1 if the allocation fails.
 * process - pointer to the previously allocated process info.
 * rq_transf - structure with allocated DPA buffers for RQ.
 */
static int rq_mem_alloc(struct flexio_process *process, struct app_transfer_wq *rq_transf)
{
	/* DBR source memory on the host (to copy). */
	__be32 dbr[2] = { 0, 0 };

	/* Allocate DPA heap memory for RQ data. */
	flexio_buf_dev_alloc(process, Q_DATA_BSIZE, &rq_transf->wqd_daddr);
	if (!rq_transf->wqd_daddr)
		return -1;

	/* Allocate DPA heap memory for RQ ring. */
	flexio_buf_dev_alloc(process, RQ_RING_BSIZE, &rq_transf->wq_ring_daddr);
	if (!rq_transf->wq_ring_daddr)
		return -1;

	/* Allocate and initialize RQ DBR memory on the DPA heap memory. */
	flexio_copy_from_host(process, dbr, sizeof(dbr), &rq_transf->wq_dbr_daddr);
	if (!rq_transf->wq_dbr_daddr)
		return -1;

	return 0;
}
#endif

#ifdef HOSTBUF
/* Set up RQ data transfer info for hostbuf mode using the combined buffer.
 * The combined buffer (data_hbuf / data_mr) was already allocated by sq_mem_alloc_hostbuf.
 * RQ occupies the first half; this function sets wqd_daddr/wqd_mkey_id accordingly and
 * allocates the RQ descriptor ring and DBR on DPA heap.
 * Returns 0 on success and -1 on failure.
 * app_ctx  - pointer to app_context structure.
 * t        - pointer to thread_ctx for this thread.
 * rq_transf - RQ transfer struct to populate.
 */
static int rq_mem_alloc_hostbuf(struct app_context *app_ctx, struct thread_ctx *t,
				struct app_transfer_wq *rq_transf)
{
	/* DBR source memory on the host (to copy). */
	__be32 dbr[2] = { 0, 0 };

	/* RQ occupies the first half of the combined buffer (allocated in sq_mem_alloc_hostbuf).
	 * Both halves share the same ibv lkey from the single MR.
	 */
	rq_transf->wqd_daddr = (flexio_uintptr_t)(uintptr_t)t->data_hbuf;
	rq_transf->wqd_mkey_id = t->data_mr->lkey;

	/* Allocate DPA heap memory for RQ ring (descriptor ring stays on DPA). */
	flexio_buf_dev_alloc(app_ctx->flexio_process, RQ_RING_BSIZE, &rq_transf->wq_ring_daddr);
	if (!rq_transf->wq_ring_daddr)
		return -1;

	/* Allocate and initialize RQ DBR on DPA heap. */
	if (flexio_copy_from_host(app_ctx->flexio_process, dbr, sizeof(dbr), &rq_transf->wq_dbr_daddr)) {
		printf("Failed to allocate RQ DBR on DPA heap\n");
		return -1;
	}

	return 0;
}
#endif

/* Initialize an RQ ring memory over the DPA heap memory.
 * RQ WQEs need to be initialized (produced) by SW so they are ready for incoming packets.
 * The WQEs are initialized over temporary host memory and then copied to the DPA.
 * Returns 0 on success and -1 if the allocation fails.
 * process   - Flex IO process.
 * rq_transf - RQ transfer struct with DPA buffer addresses.
 */
static int init_dpa_rq_ring(struct flexio_process *process, struct app_transfer_wq *rq_transf)
{
	/* RQ WQE data iterator. */
	flexio_uintptr_t wqe_data_daddr = rq_transf->wqd_daddr;
	/* RQ ring MKey. */
	uint32_t mkey_id = rq_transf->wqd_mkey_id;
	/* Temporary host memory for RQ ring. */
	struct mlx5_wqe_data_seg *rx_wqes;
	/* RQ WQE iterator. */
	struct mlx5_wqe_data_seg *dseg;
	/* Function return value. */
	int retval = 0;
	/* RQ WQE index iterator. */
	uint32_t i;

	/* Allocate temporary host memory for RQ ring.*/
	rx_wqes = calloc(1, RQ_RING_BSIZE);
	if (!rx_wqes) {
		printf("Failed to allocate memory for rx_wqes\n");
		return -1;
	}

	/* Initialize RQ WQEs'. */
	for (i = 0, dseg = rx_wqes; i < Q_DEPTH; i++, dseg++) {
		/* Set WQE's data segment to point to the relevant RQ data segment. */
		mlx5dv_set_data_seg(dseg, Q_DATA_ENTRY_BSIZE, mkey_id, wqe_data_daddr);
		/* Advance data pointer to next segment. */
		wqe_data_daddr += Q_DATA_ENTRY_BSIZE;
	}

	/* Copy RX WQEs from host to RQ ring DPA heap memory. */
	if (flexio_host2dev_memcpy(process, rx_wqes, RQ_RING_BSIZE, rq_transf->wq_ring_daddr))
		retval = -1;

	/* Free temporary host memory. */
	free(rx_wqes);
	return retval;
}

/* Initialize RQ's DBR.
 * Receive counter need to be set to number of produced WQEs.
 * Returns 0 on success and -1 if the allocation fails.
 * process   - Flex IO process.
 * rq_transf - RQ transfer struct with DPA buffer addresses.
 */
static int init_rq_dbr(struct flexio_process *process, struct app_transfer_wq *rq_transf)
{
	/* Temporary host memory for DBR value. */
	__be32 dbr[2];

	/* Set receiver counter to number of WQEs. */
	dbr[0] = htobe32(Q_DEPTH & 0xffff);
	/* Send counter is not used for RQ so it is nullified. */
	dbr[1] = htobe32(0);
	/* Copy DBR value to DPA heap memory.*/
	if (flexio_host2dev_memcpy(process, dbr, sizeof(dbr), rq_transf->wq_dbr_daddr))
		return -1;

	return 0;
}

/* Create an RQ over the DPA for receiving packets on DPA.
 * A CQ is also created for the RQ.
 * Returns 0 on success and -1 if the allocation fails.
 * app_ctx - pointer to app_context structure.
 * t       - pointer to thread_ctx for this thread.
 */
static int create_thread_rq(struct app_context *app_ctx, struct thread_ctx *t)
{
	/* Pointer to the application Flex IO process (ease of use). */
	struct flexio_process *app_fp = app_ctx->flexio_process;
	/* Attributes for the RQ's CQ. */
	struct flexio_cq_attr rqcq_attr = {0};
	/* Attributes for the RQ. */
	struct flexio_wq_attr rq_attr = {0};

	/* UAR ID for CQ/SQ from Flex IO process UAR. */
	uint32_t uar_id = flexio_uar_get_id(app_ctx->process_uar);
	/* RQ's CQ number. */
	uint32_t cq_num;

    #ifdef HOSTCQ
	/* Allocate CQ memory: ring in host memory when hostcq, else on DPA heap. */
    if (rq_cq_mem_alloc_host(app_ctx, t)) {
        printf("Failed to alloc host memory for RQ's CQ.\n");
        return -1;
    }
    #else
    if (cq_mem_alloc(app_fp, &t->rq_cq_transf)) {
        printf("Failed to alloc memory for RQ's CQ.\n");
        return -1;
    }
    #endif

	/* Set CQ depth (log) attribute. */
	rqcq_attr.log_cq_depth = LOG_Q_DEPTH;
	/* Set CQ element type attribute to 'DPA thread'.
	 * This means that a CQE on this CQ will trigger the connected DPA thread.
	 * This will be used for running the DPA program for each incoming packet on the RQ.
	 */
	rqcq_attr.element_type = FLEXIO_CQ_ELEMENT_TYPE_DPA_THREAD;
	/* Set CQ thread to this thread's event handler thread. */
	rqcq_attr.thread = flexio_event_handler_get_thread(t->pp_eh);
	/* Set CQ UAR ID attribute to the Flex IO process UAR ID.
	 * This will allow updating/arming the CQ from the DPA side.
	 */
	rqcq_attr.uar_id = uar_id;
	/* CQ DBR always on DPA heap for direct DPA access. */
	rqcq_attr.cq_dbr_daddr = t->rq_cq_transf.cq_dbr_daddr;
	/* CQ ring: host UMEM when hostcq, else DPA heap. */
    #ifdef HOSTCQ
    rqcq_attr.cq_ring_qmem.memtype    = FLEXIO_MEMTYPE_HOST;
    rqcq_attr.cq_ring_qmem.humem_offset = 0;
    rqcq_attr.cq_ring_qmem.umem_id    = t->rq_cq_ring_umem->umem_id;
    #else
    rqcq_attr.cq_ring_qmem.daddr = t->rq_cq_transf.cq_ring_daddr;
    #endif

    #if CQE_COMP==0
    rqcq_attr.cqe_comp_type = FLEXIO_CQE_COMP_NONE;
    #else
    rqcq_attr.cqe_comp_type = FLEXIO_CQE_COMP_ENABLE;
    #endif
	/* Create CQ for RQ. */
	if (flexio_cq_create(app_fp, NULL, &rqcq_attr, &t->flexio_rq_cq_ptr)) {
		printf("Failed to create Flex IO CQ\n");
		return -1;
	}

	/* Fetch RQ's CQ number to communicate to DPA side. */
	cq_num = flexio_cq_get_cq_num(t->flexio_rq_cq_ptr);
	/* Set RQ's CQ number in communication struct. */
	t->rq_cq_transf.cq_num = cq_num;
	/* Set RQ's CQ depth in communication struct. */
	t->rq_cq_transf.log_cq_depth = LOG_Q_DEPTH;
	/* Allocate RQ memory (ring and data). Data goes to host or DPA depending on mode. */
    #ifdef HOSTBUF
	if (rq_mem_alloc_hostbuf(app_ctx, t, &t->rq_transf))
    #else
	if (rq_mem_alloc(app_fp, &t->rq_transf))
    #endif
    {
		printf("Failed to allocate memory for RQ.\n");
		return -1;
	}

    #ifndef HOSTBUF
	/* Create an MKey for RQ data buffer (DPA mode only; hostbuf uses ibv lkey from MR). */
    t->rqd_mkey = create_dpa_mkey(app_ctx, t->rq_transf.wqd_daddr);
    if (!t->rqd_mkey) {
        printf("Failed to create an MKey for RQ data buffer.\n");
        return -1;
    }
    t->rq_transf.wqd_mkey_id = flexio_mkey_get_id(t->rqd_mkey);
    #endif
	/* Initialize RQ ring. */
	if (init_dpa_rq_ring(app_fp, &t->rq_transf)) {
		printf("Failed to init RQ ring.\n");
		return -1;
	}

	/* Set RQ depth (log) attribute. */
	rq_attr.log_wq_depth = LOG_Q_DEPTH;
	/* Set RQ protection domain attribute to be the same as the Flex IO process. */
	rq_attr.pd = app_ctx->process_pd;
	/* Set RQ DBR memory type to DPA heap memory. */
	rq_attr.wq_dbr_qmem.memtype = FLEXIO_MEMTYPE_DPA;
	/* Set RQ DBR memory address. */
	rq_attr.wq_dbr_qmem.daddr = t->rq_transf.wq_dbr_daddr;
	/* Set RQ ring memory address. */
	rq_attr.wq_ring_qmem.daddr = t->rq_transf.wq_ring_daddr;
	/* Create the Flex IO RQ.
	 * Second argument is NULL as RQ is created on the same GVMI as the process.
	 */
	if (flexio_rq_create(app_fp, NULL, cq_num, &rq_attr, &t->flexio_rq_ptr)) {
		printf("Failed to create Flex IO RQ.\n");
		return -1;
	}

	/* Fetch RQ's number to communicate to DPA side. */
	t->rq_transf.wq_num = flexio_rq_get_wq_num(t->flexio_rq_ptr);
	if (init_rq_dbr(app_fp, &t->rq_transf)) {
		printf("Failed to init RQ DBR.\n");
		return -1;
	}

	return 0;
}

/* Creates a Flex IO SDK event handler for a single thread.
 * The event handler is pinned to a dedicated EU via FLEXIO_AFFINITY_STRICT so that
 * the static app_ctxs[thread_index] array on the DPA side is always accessed by the
 * same EU (no concurrent access, no locking needed).
 * Returns 0 on success and -1 if the allocation fails.
 * app_ctx - pointer to app_context structure.
 * t       - pointer to thread_ctx for this thread.
 */
static int create_thread_event_handler(struct app_context *app_ctx, struct thread_ctx *t)
{
	/* Event handler creation attributes. */
	struct flexio_event_handler_attr eh_attr = {0};

	/* Set function stub to the stub created by DPACC and declared in the host application. */
	eh_attr.host_stub_func = flexio_pp_dev;
	/* Pin each event handler to a dedicated EU so that array index i is always served by
	 * EU i, making the device-side static array access safe without locks.
	 */
	eh_attr.affinity.type = FLEXIO_AFFINITY_STRICT;
	eh_attr.affinity.id = t->thread_index;
	/* Create the Flex IO event handler object. */
	if (flexio_event_handler_create(app_ctx->flexio_process, &eh_attr, &t->pp_eh)) {
		printf("Failed to create Flex IO event handler\n");
		return -1;
	}

	return 0;
}


static int read_thread_h2d(struct app_context *ctx, struct thread_ctx *t, struct host2dev_packet_processor_data *h2d_snapshot)
{
	struct flexio_mem src = {0};
	struct flexio_mem dst = {0};

	src.mem_type = FLEXIO_MEMTYPE_DPA;
	src.daddr = t->app_data_daddr;
	dst.mem_type = FLEXIO_MEMTYPE_HOST;
	dst.haddr = (uintptr_t)h2d_snapshot;

	if (flexio_memcpy(ctx->flexio_process, &src, &dst, sizeof(struct host2dev_packet_processor_data)) !=
	    FLEXIO_STATUS_SUCCESS) {
		printf("Failed to read thread %u stats from DPA memory\n", t->thread_index);
		return -1;
	}

	return 0;
}


/* Copy per-thread application information to DPA.
 * DPA side needs queue information in order to process the packets.
 * The DPA heap memory address will be passed as the event handler argument.
 * Returns 0 if success and -1 if the copy failed.
 * app_ctx - pointer to app_context structure.
 * t       - pointer to thread_ctx for this thread.
 */
static int copy_thread_data_to_dpa(struct app_context *app_ctx, struct thread_ctx *t)
{
	/* Size of application information struct. */
	uint64_t struct_bsize = sizeof(struct host2dev_packet_processor_data);
	/* Temporary application information struct to copy. */
	struct host2dev_packet_processor_data *h2d_data;
	/* Function return value. */
	int ret = 0;

	/* Allocate memory for temporary struct to copy. */
	h2d_data = calloc(1, struct_bsize);
	if (!h2d_data) {
		printf("Failed to allocate memory for h2d_data\n");
		return -1;
	}

	/* Set SQ's CQ information. */
	h2d_data->sq_cq_transf = t->sq_cq_transf;
	/* Set SQ's information. */
	h2d_data->sq_transf = t->sq_transf;
	/* Set RQ's CQ information. */
	h2d_data->rq_cq_transf = t->rq_cq_transf;
	/* Set RQ's information. */
	h2d_data->rq_transf = t->rq_transf;
	/* Set thread index so DPA selects the correct app_ctxs[] slot. */
	h2d_data->thread_index = t->thread_index;
	/* Set APP data info for first run. */
	h2d_data->not_first_run = 0;
	/* Propagate host-buffer mode, window ID, zero-copy, hostcq, and hostdecomp to DPA. */
	h2d_data->window_id = app_ctx->window ? flexio_window_get_id(app_ctx->window) : 0;
	/* When hostcq is on, pass the host VA of the CQ ring in cq_ring_daddr.
	 * DPA interprets this as a host VA to map through the window.
	 */
    #if CQE_COMP==2
    h2d_data->thread_memo = (flexio_uintptr_t)((char *)t->data_hbuf + 2 * Q_DATA_BSIZE + CQ_BSIZE);
    #else
    h2d_data->thread_memo = NULL;
    #endif
    #ifdef HOSTCQ
    h2d_data->rq_cq_transf.cq_ring_daddr = (flexio_uintptr_t)(uintptr_t)((char *)t->data_hbuf + 2 * Q_DATA_BSIZE);
    #endif

	/* Copy to DPA heap memory.
	 * Allocated DPA heap memory address will be kept in t->app_data_daddr.
	 */
	if (flexio_copy_from_host(app_ctx->flexio_process, h2d_data, struct_bsize,
				  &t->app_data_daddr)) {
		printf("Failed to copy application information to DPA.\n");
		ret = -1;
	}

	/* Free temporary host memory. */
	free(h2d_data);
	return ret;
}

/* Clean up previously allocated steering rules for one thread.
 * Returns 0 on success and -1 if any destroy failed.
 * t - pointer to thread_ctx for this thread.
 */
static int clean_up_thread_rules(struct thread_ctx *t)
{
	int err = 0;

	/* Clean up rx rule if created */
	if (t->rx_rule && destroy_rule(t->rx_rule)) {
		printf("Failed to destroy rx rule\n");
		err = -1;
	}

	/* Clean up rx matcher if created */
	if (t->rx_matcher && destroy_matcher(t->rx_matcher)) {
		printf("Failed to destroy rx matcher\n");
		err = -1;
	}

	/* Clean up tx rule for vport if created */
	if (t->tx_rule_vport && destroy_rule(t->tx_rule_vport)) {
		printf("Failed to destroy tx rule vport\n");
		err = -1;
	}

	/* Clean up tx rule for table if created */
	if (t->tx_rule_table && destroy_rule(t->tx_rule_table)) {
		printf("Failed to destroy tx rule\n");
		err = -1;
	}

	/* Clean up tx matcher if created */
	if (t->tx_matcher && destroy_matcher(t->tx_matcher)) {
		printf("Failed to destroy tx matcher\n");
		err = -1;
	}

	return err;
}

/* Clean up previously allocated RQ for one thread.
 * Returns 0 on success and -1 if the destroy failed.
 * app_ctx - pointer to app_context structure.
 * t       - pointer to thread_ctx for this thread.
 */
static int clean_up_thread_rq(struct app_context *app_ctx, struct thread_ctx *t)
{
	int err = 0;

	/* Clean up rq pointer if created */
	if (t->flexio_rq_ptr && flexio_rq_destroy(t->flexio_rq_ptr)) {
		printf("Failed to destroy RQ\n");
		err = -1;
	}

	/* Clean up memory key for rqd if created (DPA mode only) */
    #ifndef HOSTBUF
	if (t->rqd_mkey && flexio_device_mkey_destroy(t->rqd_mkey)) {
		printf("Failed to destroy mkey RQD\n");
		err = -1;
	}
    #endif

	/* Clean up DBR daddr if created */
	if (t->rq_transf.wq_dbr_daddr &&
	    flexio_buf_dev_free(app_ctx->flexio_process, t->rq_transf.wq_dbr_daddr)) {
		printf("Failed to free rq_transf.wq_dbr_daddr\n");
		err = -1;
	}

	/* Clean up wq_ring_daddr for rq_transf if created */
	if (t->rq_transf.wq_ring_daddr &&
	    flexio_buf_dev_free(app_ctx->flexio_process, t->rq_transf.wq_ring_daddr)) {
		printf("Failed to free rq_transf.wq_ring_daddr\n");
		err = -1;
	}

    #ifndef HOSTBUF
    if (t->rq_transf.wqd_daddr &&
        flexio_buf_dev_free(app_ctx->flexio_process, t->rq_transf.wqd_daddr)) {
        printf("Failed to free rq_transf.wqd_daddr\n");
        err = -1;
    }
    #else
	/* In hostbuf mode the combined buffer and its MR are freed in clean_up_thread_sq. */
    #endif

	if (t->flexio_rq_cq_ptr && flexio_cq_destroy(t->flexio_rq_cq_ptr)) {
		printf("Failed to destroy RQ CQ\n");
		err = -1;
	}

	/* Deregister DEVX UMEM for host CQ ring after CQ is destroyed (hostcq mode).
	 * The backing memory (combined buffer) is freed later in clean_up_thread_sq.
	 */
	if (t->rq_cq_ring_umem && mlx5dv_devx_umem_dereg(t->rq_cq_ring_umem)) {
		printf("Failed to deregister UMEM for host RQ CQ ring\n");
		err = -1;
	}

	/* Free DPA heap CQ ring memory (non-hostcq mode only).
	 * When hostcq is on, cq_ring_daddr holds the host VA (= 0 in our tracking),
	 * so this condition is always false and we skip the free safely.
	 */
	if (t->rq_cq_transf.cq_ring_daddr &&
	    flexio_buf_dev_free(app_ctx->flexio_process, t->rq_cq_transf.cq_ring_daddr)) {
		printf("Failed to free rq_cq_transf.cq_ring_daddr\n");
		err = -1;
	}

	if (t->rq_cq_transf.cq_dbr_daddr &&
	    flexio_buf_dev_free(app_ctx->flexio_process, t->rq_cq_transf.cq_dbr_daddr)) {
		printf("Failed to free rq_cq_transf.cq_dbr_daddr\n");
		err = -1;
	}

	return err;
}

/* Clean up previously allocated SQ for one thread.
 * Returns 0 on success and -1 if the destroy failed.
 * app_ctx - pointer to app_context structure.
 * t       - pointer to thread_ctx for this thread.
 */
static int clean_up_thread_sq(struct app_context *app_ctx, struct thread_ctx *t)
{
	int err = 0;

	if (t->flexio_sq_ptr && flexio_sq_destroy(t->flexio_sq_ptr)) {
		printf("Failed to destroy SQ\n");
		err = -1;
	}

	/* Clean up memory key for sqd if created (DPA mode only) */
    #ifndef HOSTBUF
	if (t->sqd_mkey && flexio_device_mkey_destroy(t->sqd_mkey)) {
		printf("Failed to destroy mkey SQD\n");
		err = -1;
	}
    #endif

	if (t->sq_transf.wq_ring_daddr &&
	    flexio_buf_dev_free(app_ctx->flexio_process, t->sq_transf.wq_ring_daddr)) {
		printf("Failed to free sq_transf.wq_ring_daddr\n");
		err = -1;
	}

    #ifdef HOSTBUF
    /* Host buffer mode: deregister the single combined MR and free the buffer.
    * Both RQ and SQ halves are covered by data_mr / data_hbuf.
    */
    if (t->data_mr && ibv_dereg_mr(t->data_mr)) {
        printf("Failed to deregister combined data MR\n");
        err = -1;
    }
    free(t->data_hbuf);
    t->data_hbuf = NULL;
    #else
    if (t->sq_transf.wqd_daddr &&
        flexio_buf_dev_free(app_ctx->flexio_process, t->sq_transf.wqd_daddr)) {
        printf("Failed to free sq_transf.wqd_daddr\n");
        err = -1;
    }
    #endif

	if (t->flexio_sq_cq_ptr && flexio_cq_destroy(t->flexio_sq_cq_ptr)) {
		printf("Failed to destroy SQ CQ\n");
		err = -1;
	}

	if (t->sq_cq_transf.cq_ring_daddr &&
	    flexio_buf_dev_free(app_ctx->flexio_process, t->sq_cq_transf.cq_ring_daddr)) {
		printf("Failed to free sq_cq_transf.cq_ring_daddr\n");
		err = -1;
	}

	if (t->sq_cq_transf.cq_dbr_daddr &&
	    flexio_buf_dev_free(app_ctx->flexio_process, t->sq_cq_transf.cq_dbr_daddr)) {
		printf("Failed to free sq_cq_transf.cq_dbr_daddr\n");
		err = -1;
	}

	return err;
}

/* Set by SIGINT handler so the prompt loop exits cleanly on Ctrl-C. */
static volatile int g_quit_prompt = 0;

static void sigint_handler(int signum)
{
	(void)signum;
	g_quit_prompt = 1;
}

/* Interactive prompt loop — displays real-time stats from all DPA threads.
 * Installs a SIGINT handler so Ctrl-C exits cleanly.
 * app_ctx - pointer to app_context holding the thread array and process handle.
 * Returns 0 on success, -1 on error.
 *
 * Commands:
 *   1 - show how many DPA threads are alive (heartbeat changed over 1 s)
 *   2 - show total throughput in Mpps (packet count delta over 1 s)
 *   0 - quit
 *   <empty> / anything else - ignored
 */
static int system_prompt(struct app_context *app_ctx)
{
	struct sigaction sa = {0};
	struct host2dev_packet_processor_data *snap_before, *snap_after;
	char line[64];
	int n = app_ctx->num_threads;
	int i, cmd;
	char *p;

	/* Install SIGINT handler; return from this function when the process gets SIGINT. */
	sa.sa_handler = sigint_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (sigaction(SIGINT, &sa, NULL) < 0) {
		printf("Failed to install SIGINT handler\n");
		return -1;
	}

	snap_before = calloc(n, sizeof(*snap_before));
	snap_after  = calloc(n, sizeof(*snap_after));
	if (!snap_before || !snap_after) {
		free(snap_before);
		free(snap_after);
		printf("Failed to allocate snapshot buffers\n");
		return -1;
	}

	printf("Commands: 1=alive threads  2=Mpps  3=compress percentage%%  0=quit\n");

	while (!g_quit_prompt) {
		printf("> ");
		fflush(stdout);

		if (!fgets(line, sizeof(line), stdin))
			break;

		/* Skip empty / whitespace-only input. */
		p = line;
		while (*p == ' ' || *p == '\t')
			p++;
		if (*p == '\n' || *p == '\r' || *p == '\0')
			continue;

		cmd = atoi(p);

		if (cmd == 0) {
			break;
		} else if (cmd == 1) {
			/* Count alive threads: heartbeat must change within 1 second. */
			int alive = 0;

			for (i = 0; i < n; i++)
				read_thread_h2d(app_ctx, &app_ctx->threads[i], &snap_before[i]);
			usleep(500000);
			for (i = 0; i < n; i++) {
				read_thread_h2d(app_ctx, &app_ctx->threads[i], &snap_after[i]);
				if (snap_after[i].heartbeat != snap_before[i].heartbeat)
					alive++;
			}
			printf("Alive DPA threads: %d / %d\n", alive, n);
		} else if (cmd == 2) {
			/* Measure aggregate packet rate over 1 second, display as Mpps. */
			uint64_t total_pps = 0;

			for (i = 0; i < n; i++)
				read_thread_h2d(app_ctx, &app_ctx->threads[i], &snap_before[i]);
			usleep(500000);
			for (i = 0; i < n; i++) {
				read_thread_h2d(app_ctx, &app_ctx->threads[i], &snap_after[i]);
				total_pps += snap_after[i].report_packets_count -
					     snap_before[i].report_packets_count;
			}
			printf("Throughput: %.3f Mpps\n", (double)total_pps / 1e6 * 2);
		} else if (cmd == 3) {
			/* Measure comp_packets / packets over 1 second. display as percentage */
			uint64_t total_pkts = 0, total_comp = 0;

			for (i = 0; i < n; i++)
				read_thread_h2d(app_ctx, &app_ctx->threads[i], &snap_before[i]);
			usleep(500000);
			for (i = 0; i < n; i++) {
				read_thread_h2d(app_ctx, &app_ctx->threads[i], &snap_after[i]);
				total_pkts += snap_after[i].report_packets_count -
					      snap_before[i].report_packets_count;
				total_comp += snap_after[i].report_comp_packets_count -
					      snap_before[i].report_comp_packets_count;
			}
			if (total_pkts > 0)
				printf("Compress percentage: %.2f%%\n",
				       (double)total_comp / (double)total_pkts * 100.0);
			else
				printf("Compress percentage: N/A (no packets received)\n");
		} else if (cmd == 4) {
            if (app_ctx->decomp_ctx == NULL) {
                printf("hostdecomp not working");
                continue;
            }
            for (i = 0; i < 8; i++) {
                struct hostdecomp_queue_ctx *current_qctx =  &app_ctx->decomp_ctx->queues[i];
                printf("queue %d's cq_idx = %u\n", i, current_qctx->cq_idx);
            }
        } else if (cmd == 5) {
            if (app_ctx->decomp_ctx == NULL) {
                printf("hostdecomp not working");
                continue;
            }
            for (i = 0; i < 8; i++) {
                struct hostdecomp_queue_ctx *current_qctx =  &app_ctx->decomp_ctx->queues[i];
                printf("dpa thread %d's memo = %u, memo_ptr = %lx\n", i, current_qctx->dpa_memo->memo[i], (uint64_t)&current_qctx->dpa_memo->memo[i]);
            }
        } else if (cmd == 6) {
            if (app_ctx->decomp_ctx == NULL) {
                printf("hostdecomp not working");
                continue;
            }
            for (i = 0; i < 8; i++) {
                struct hostdecomp_queue_ctx *current_qctx =  &app_ctx->decomp_ctx->queues[i];
                printf("cpu %d's memo = %u\n", i, current_qctx->cpu_memo->memo[i]);
            }
        } else if (cmd == 7) {
            if (app_ctx->decomp_ctx == NULL) {
                printf("hostdecomp not working");
                continue;
            }
            for (i = 0; i < 4; i++) {
                printf("queue %d, ----------------------\n", i);
                struct hostdecomp_queue_ctx *current_qctx =  &app_ctx->decomp_ctx->queues[i];
                for (int j = 0; j < 8; j++) {
                    struct host_cqe64 *checking_cqe = (&current_qctx->cq_ring_addr[((uint32_t)current_qctx->dpa_memo->memo[i] - 4U + (uint32_t)j) & 0x7f]);
                    printf("%d's idx=%u, opown = %x\n", j - 4, ((uint32_t)current_qctx->dpa_memo->memo[i] - 4U + (uint32_t)j) & 0x7f, checking_cqe->op_own);
                }
            }
        }

		/* else: ignore unrecognized input */
	}

	free(snap_before);
	free(snap_after);
	return 0;
}

#if CQE_COMP==2
static struct host_cqe64 *hostdecomp_entry_addr(struct hostdecomp_queue_ctx *qctx,
						  uint32_t cq_idx)
{
	uint32_t mask = (1u << qctx->log_cq_depth) - 1u;

	return &qctx->cq_ring_addr[cq_idx & mask];
}

static void hostdecomp_advance(struct hostdecomp_queue_ctx *qctx, uint32_t cqes)
{
	uint32_t mask = (1u << qctx->log_cq_depth) - 1u;
	uint32_t i;

	for (i = 0; i < cqes; i++) {
		qctx->cq_idx++;
		if (!(qctx->cq_idx & mask))
			qctx->cq_hw_owner_bit = !qctx->cq_hw_owner_bit;
	}
}

static int hostdecomp_decompress(struct hostdecomp_ctx *ctx, uint32_t queue_idx, uint32_t cq_idx) {
	uint32_t mask = (1u << LOG_CQ_DEPTH) - 1u;
    uintptr_t title_cqe_addr = (uintptr_t) &ctx->queues[queue_idx].cq_ring_addr[(cq_idx-1U) & mask];
    uintptr_t compressed_cqe_addr = (uintptr_t) &ctx->queues[queue_idx].cq_ring_addr[(cq_idx) & mask];

    uint8x16x4_t title_cqe = vld1q_u8_x4((const uint8_t *) title_cqe_addr);
    uint8x16x4_t compressed_cqe = vld1q_u8_x4((const uint8_t *) compressed_cqe_addr);
    printf("hhii\n");

    if (((vgetq_lane_u8(title_cqe.val[3], 15)) & 0x0C) == 0x0C) {
        printf("error1\n");
        return -1;
    }
    if (((vgetq_lane_u8(compressed_cqe.val[3], 15)) & 0x0C) != 0x0C) {
        printf("error2\n");
        return -1;
    }
    //do something
    return 0;
}

/* Decompress a compressed CQE block in-place in host memory.
 * Mirrors the DPA-side decompress_if_cqe_is_compressed logic but runs on host CPU.
 * Returns 0 on success, -1 if no title CQE is available.
 */
static int hostdecomp_decompress_current(struct hostdecomp_queue_ctx *qctx,
					 const struct host_mini_cqe64 *compressed_cqe,
                     struct host_cqe64 *title_cqe,
					 uint32_t mini_cqe_num
					 )
{
    uint32_t mask = (1u << qctx->log_cq_depth) - 1u;

    uint64_t mini_cqes[7] = {0};
    for (uint32_t i = 0; i < mini_cqe_num; i++) {
        mini_cqes[i] = compressed_cqe->mini_cqe[i];
    }

    struct host_cqe64 *current_cqe = NULL;
    uint8_t current_own_bit = (title_cqe->op_own & 0x1);
    { // i = 0
        current_cqe = &qctx->cq_ring_addr[(qctx->cq_idx) & mask];
        current_own_bit = ((qctx->cq_idx) & mask) ? current_own_bit : !current_own_bit;
    }
	for (uint32_t i = 1; i < mini_cqe_num; i++) {
        current_cqe = &qctx->cq_ring_addr[(qctx->cq_idx + i) & mask];
        current_own_bit = ((qctx->cq_idx + i) & mask) ? current_own_bit : !current_own_bit;

        memcpy(current_cqe, title_cqe, 64);

        current_cqe->byte_cnt = (__be32) (mini_cqes[i] >> 32) & 0xFFFFFFFF;
        current_cqe->rsvd00[3] = (__be32) (mini_cqes[i]) & 0xFFFFFFFF;
        current_cqe->wqe_counter = (__be16) htobe16(be16toh(title_cqe->wqe_counter) + i + 1U);
        current_cqe->rsvd24[0] = (__be32) htobe32(i);

        current_cqe->op_own = (title_cqe->op_own & (~0x01)) | (current_own_bit & 0x01);
	}
    { // i = 0
        current_own_bit = (title_cqe->op_own & 0x1);
        current_cqe = &qctx->cq_ring_addr[(qctx->cq_idx) & mask];
        current_own_bit = ((qctx->cq_idx) & mask) ? current_own_bit : !current_own_bit;

        memcpy(current_cqe, title_cqe, 63);

        current_cqe->byte_cnt = (__be32) (mini_cqes[0] >> 32) & 0xFFFFFFFF;
        current_cqe->rsvd00[3] = (__be32) (mini_cqes[0]) & 0xFFFFFFFF;
        current_cqe->wqe_counter = (__be16) htobe16(be16toh(title_cqe->wqe_counter) + 1U);
        current_cqe->rsvd24[0] = (__be32) htobe32(0xDEADBEEF);

        __atomic_thread_fence(__ATOMIC_RELEASE);
        current_cqe->op_own = (title_cqe->op_own & (~0x01)) | (current_own_bit & 0x01);
    }
        title_cqe->rsvd24[0] = (__be32) htobe32(0xEEEEEEEE);

	return 0;
}

void print_uint8x16x4(uint8x16x4_t d);
void print_uint8x16x4(uint8x16x4_t d) {
    printf("-----------------------------------\n");
    for (int i = 0; i < 4; i++) {
        // 각 16바이트 레지스터를 8바이트씩 두 줄로 출력
        // 상단 8바이트 (Lane 0~7)
        printf("%02x %02x %02x %02x %02x %02x %02x %02x\n",
               vgetq_lane_u8(d.val[i], 0), vgetq_lane_u8(d.val[i], 1),
               vgetq_lane_u8(d.val[i], 2), vgetq_lane_u8(d.val[i], 3),
               vgetq_lane_u8(d.val[i], 4), vgetq_lane_u8(d.val[i], 5),
               vgetq_lane_u8(d.val[i], 6), vgetq_lane_u8(d.val[i], 7));

        // 하단 8바이트 (Lane 8~15)
        printf("%02x %02x %02x %02x %02x %02x %02x %02x\n",
               vgetq_lane_u8(d.val[i], 8), vgetq_lane_u8(d.val[i], 9),
               vgetq_lane_u8(d.val[i], 10), vgetq_lane_u8(d.val[i], 11),
               vgetq_lane_u8(d.val[i], 12), vgetq_lane_u8(d.val[i], 13),
               vgetq_lane_u8(d.val[i], 14), vgetq_lane_u8(d.val[i], 15));
    }
}

void print_memoblock(uintptr_t d);
void print_memoblock(uintptr_t d) {
    uint8_t *k = (uint8_t *) d;
    printf("-----------------------------------\n");
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            printf("%x ", *(k+8*i+j));
        }
        printf("\n");
    }
}


/* Host observer thread: rotates across all DPA threads' host-memory CQ rings.
 * When a compressed CQE block is found it decompresses in-place so the DPA can
 * process the resulting regular CQEs on its next invocation.
 */
static void *hostdecomp_poll_thread(void *arg)
{
    (void) print_uint8x16x4;
    (void) print_memoblock;
    (void) hostdecomp_decompress_current;
    (void) hostdecomp_advance;
    (void) hostdecomp_entry_addr;
    int core_num = 15;
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset); 
    CPU_SET(core_num, &cpuset);
    pthread_t current_thread = pthread_self();
    int result = pthread_setaffinity_np(current_thread, sizeof(cpu_set_t), &cpuset);
    if (result != 0) {
        perror("pthread_setaffinity_np failed");
    } 

	struct hostdecomp_ctx *ctx = arg;

	if (!ctx->num_queues || !ctx->queues)
		return NULL;

    uint32_t memo_block_count = (uint32_t)((ctx->num_queues+31U) / 32);
    struct hostdecomp_thread_memo *dpa_memo_addr = ctx->queues[0].dpa_memo;
    struct hostdecomp_thread_memo *cpu_memo_addr = ctx->queues[0].cpu_memo;

    sleep(1);
	while (!ctx->stop) {
        for (uint32_t block_idx = 0; block_idx < memo_block_count; block_idx++) {
            sleep(1);
            uintptr_t dpa_block_addr = (uintptr_t) &dpa_memo_addr->memo[(block_idx<<5)];
            uintptr_t cpu_block_addr = (uintptr_t) &cpu_memo_addr->memo[(block_idx<<5)];
            uint8x16x4_t dpa_block = vld1q_u8_x4((const uint8_t *) dpa_block_addr);
            uint8x16x4_t cpu_block = vld1q_u8_x4((const uint8_t *) cpu_block_addr);

            printf("%lx, %lx\n", dpa_block_addr, cpu_block_addr);
            print_uint8x16x4(dpa_block);
            print_memoblock(dpa_block_addr);
            for (uint32_t i = 0; i < 4; i++) {
                uint8x16_t diff_vec = veorq_u8(dpa_block.val[i], cpu_block.val[i]);
                if (vmaxvq_u8(diff_vec) != 0) {

                    uint16x8_t d_u16 = vreinterpretq_u16_u8(dpa_block.val[i]);
                    uint16x8_t c_u16 = vreinterpretq_u16_u8(cpu_block.val[i]);

                    if (vgetq_lane_u16(d_u16, 0) != vgetq_lane_u16(c_u16, 0)) {
                        uint16_t cq_idx_for_check = vgetq_lane_u16(d_u16, 0);
                        hostdecomp_decompress(ctx, (block_idx<<5)+(i<<3)+0U, (uint32_t)cq_idx_for_check);
                    }
                    if (vgetq_lane_u16(d_u16, 1) != vgetq_lane_u16(c_u16, 1)) {
                        uint16_t cq_idx_for_check = vgetq_lane_u16(d_u16, 1);
                        hostdecomp_decompress(ctx, (block_idx<<5)+(i<<3)+1U, (uint32_t)cq_idx_for_check);
                    }
                    if (vgetq_lane_u16(d_u16, 2) != vgetq_lane_u16(c_u16, 2)) {
                        uint16_t cq_idx_for_check = vgetq_lane_u16(d_u16, 2);
                        hostdecomp_decompress(ctx, (block_idx<<5)+(i<<3)+2U, (uint32_t)cq_idx_for_check);
                    }
                    if (vgetq_lane_u16(d_u16, 3) != vgetq_lane_u16(c_u16, 3)) {
                        uint16_t cq_idx_for_check = vgetq_lane_u16(d_u16, 3);
                        hostdecomp_decompress(ctx, (block_idx<<5)+(i<<3)+3U, (uint32_t)cq_idx_for_check);
                    }
                    if (vgetq_lane_u16(d_u16, 4) != vgetq_lane_u16(c_u16, 4)) {
                        uint16_t cq_idx_for_check = vgetq_lane_u16(d_u16, 4);
                        hostdecomp_decompress(ctx, (block_idx<<5)+(i<<3)+4U, (uint32_t)cq_idx_for_check);
                    }
                    if (vgetq_lane_u16(d_u16, 5) != vgetq_lane_u16(c_u16, 5)) {
                        uint16_t cq_idx_for_check = vgetq_lane_u16(d_u16, 5);
                        hostdecomp_decompress(ctx, (block_idx<<5)+(i<<3)+5U, (uint32_t)cq_idx_for_check);
                    }
                    if (vgetq_lane_u16(d_u16, 6) != vgetq_lane_u16(c_u16, 6)) {
                        uint16_t cq_idx_for_check = vgetq_lane_u16(d_u16, 6);
                        hostdecomp_decompress(ctx, (block_idx<<5)+(i<<3)+6U, (uint32_t)cq_idx_for_check);
                    }
                    if (vgetq_lane_u16(d_u16, 7) != vgetq_lane_u16(c_u16, 7)) {
                        uint16_t cq_idx_for_check = vgetq_lane_u16(d_u16, 7);
                        hostdecomp_decompress(ctx, (block_idx<<5)+(i<<3)+7U, (uint32_t)cq_idx_for_check);
                    }
                }
            }

            vst1q_u8_x4((uint8_t *) cpu_block_addr, dpa_block);
        }
	}

	return NULL;
}

/* Start the host decompression observer for all threads that have hostdecomp_enable set.
 * Returns 0 on success (including the case where no threads need it), -1 on error.
 */
static int hostdecomp_start(struct hostdecomp_ctx *ctx, struct app_context *app_ctx)
{
	uint32_t i, active = 0;

	memset(ctx, 0, sizeof(*ctx));

	for (i = 0; i < (uint32_t)app_ctx->num_threads; i++) {
        active++;
	}

	if (!active)
		return 0;

	ctx->queues = calloc(app_ctx->num_threads, sizeof(*ctx->queues));
	if (!ctx->queues) {
		printf("hostdecomp: failed to allocate queue contexts\n");
		return -1;
	}
	ctx->num_queues = (uint32_t)app_ctx->num_threads;

	for (i = 0; i < (uint32_t)app_ctx->num_threads; i++) {
		struct hostdecomp_queue_ctx *qctx = &ctx->queues[i];
		struct thread_ctx *t = &app_ctx->threads[i];

		/* CQ ring lives in the third region of the combined host buffer. */
		qctx->cq_ring_addr   = (struct host_cqe64 *)((char *)t->data_hbuf + 2 * Q_DATA_BSIZE);
		qctx->thread_index   = t->thread_index;
		qctx->cq_idx         = 0;
		qctx->log_cq_depth   = LOG_Q_DEPTH;
		qctx->cq_hw_owner_bit = 1;
        qctx->dpa_memo       = (struct hostdecomp_thread_memo *)((char *)t->data_hbuf + 2 * Q_DATA_BSIZE + CQ_BSIZE);
        qctx->cpu_memo       = (struct hostdecomp_thread_memo *)((char *)t->data_hbuf + 2 * Q_DATA_BSIZE + CQ_BSIZE + sizeof(struct hostdecomp_thread_memo));
	}

	if (pthread_create(&ctx->thread, NULL, hostdecomp_poll_thread, ctx)) {
		printf("hostdecomp: failed to start observer thread\n");
		free(ctx->queues);
		ctx->queues     = NULL;
		ctx->num_queues = 0;
		return -1;
	}

	ctx->thread_started = 1;
	printf("hostdecomp observer started for %u DPA thread(s)\n", active);
	return 0;
}

/* Stop the host decompression observer thread and print final latency stats. */
static int hostdecomp_stop(struct hostdecomp_ctx *ctx)
{
	if (!ctx->thread_started)
		return 0;

	ctx->stop = 1;
	if (pthread_join(ctx->thread, NULL)) {
		printf("hostdecomp: failed to join observer thread\n");
		return -1;
	}

	free(ctx->queues);
	ctx->queues         = NULL;
	ctx->num_queues     = 0;
	ctx->thread_started = 0;
	return 0;
}
#endif

/* dev msg stream buffer built from chunks of 2^FLEXIO_MSG_DEV_LOG_DATA_CHUNK_BSIZE each */
#define MSG_HOST_BUFF_BSIZE (512 * L2V(FLEXIO_MSG_DEV_LOG_DATA_CHUNK_BSIZE))

/* Application name in string format for Flex IO app get. */
#define DEV_APP_NAME_STR(_app_name) #_app_name
#define DEV_APP_NAME_XSTR(_app_name) DEV_APP_NAME_STR(_app_name)

/* Main host side function.
 * Responsible for allocating resources and making preparations for DPA side invocation.
 */
int main(int argc, char **argv)
{
	/* Flex IO app get selection attributes. */
	struct flexio_app_select_attr flexio_app_sel_attr = {0};
	/* Message stream attributes. */
	struct flexio_msg_stream_attr stream_fattr = {0};
	/* Pointer to the application Flex IO process (ease of use). */
	struct flexio_process *app_fp = NULL;
	/* Application context. */
	struct app_context app_ctx = {0};
	/* IBV port attributes. */
	struct ibv_port_attr port_attr;
	/* Debug token */
	uint64_t udbg_token;
	/* Mode of working - for nic (host) or for dpu (default) */
	int nic_mode = 0;
	/* Number of DPA threads to create (default 1 for backward compatibility) */
	uint32_t num_threads = 1;
	/* Host decomp observer context. */
    #if CQE_COMP==2
	struct hostdecomp_ctx hostdecomp_ctx = {0};
    app_ctx.decomp_ctx = &hostdecomp_ctx;
    #endif
	/* Loop index */
	int i;
	/* Buffer for fread */
	// char buf[2];
	/* Execution status value. */
	int err;

	printf("Welcome to 'Flex IO SDK packet processing' sample app.\n");

	/* Check input includes at least a device name. */
	if (argc < 2) {
		printf("Usage: %s <mlx5 device> [--nic-mode] [--threads N]\n",
		       argv[0]);
		return -1;
	}

	/* Parse optional arguments. */
	for (i = 2; i < argc; ) {
		if (!strcmp(argv[i], "--nic-mode")) {
			nic_mode = 1;
			i++;
		} else if (!strcmp(argv[i], "--threads")) {
			char *endptr;
			unsigned long val;

			if (i + 1 >= argc) {
				printf("--threads requires a value\n");
				return -1;
			}
			val = strtoul(argv[i + 1], &endptr, 10);
			if (!endptr || *endptr || val == 0 || val > APP_MAX_DPA_THREADS) {
				printf("--threads value must be 1..%d\n", APP_MAX_DPA_THREADS);
				return -1;
			}
			num_threads = (uint32_t)val;
			i += 2;
		} else {
			printf("Unknown argument: %s\n", argv[i]);
			printf("Usage: %s <mlx5 device> [--nic-mode] [--threads N]\n",
			       argv[0]);
			return -1;
		}
	}

	app_ctx.num_threads = (int)num_threads;

	/* Check if the application run with root privileges */
	if (geteuid()) {
		printf("Failed - the application must run with root privileges\n");
		return -1;
	}

	/* Create an IBV device context by opening the provided IBV device. */
	err = app_open_ibv_ctx(&app_ctx, argv[1]);
	if (err)
		return -1;

	/* Retrieve the attributes of the device port */
	if (ibv_query_port(app_ctx.ibv_ctx, 1, &port_attr)) {
		printf("Failed to query IBV port attributes\n");
		err = -1;
		goto cleanup;
	}

	/* Check if the device is a valid Ethernet device. */
	if (port_attr.link_layer != IBV_LINK_LAYER_ETHERNET) {
		printf("IBV port is not Ethernet, state: %d\n", port_attr.link_layer);
		err = -1;
		goto cleanup;
	}

	/* Set current version for API. */
	if (flexio_version_set(FLEXIO_VER_USED)) {
		printf("Failed to set version in FlexIO API.\n");
		err = -1;
		goto cleanup;
	}

	/* Get Flex IO application struct for used device. */
	/* Set app name to match. */
	flexio_app_sel_attr.app_name = DEV_APP_NAME_XSTR(DEV_APP_NAME);
	/* Set HW platform to default - this will auto-select the appropriate program. */
	flexio_app_sel_attr.hw_model_id = FLEXIO_HW_MODEL_DEF;
	/* Set IBV device to use for HW model query. */
	flexio_app_sel_attr.ibv_ctx = app_ctx.ibv_ctx;

	/* Get a Flex IO application.
	 * DPACC created Flex IO application per HW model. Match the select attributes to the
	 * found applications and return the matching one. Name must match. HW model is matched
	 * According to the queried HW model for the device. If no exact match is found a program
	 * built to an older HW model will be selected.
	 */
	err = flexio_app_get(&flexio_app_sel_attr, &app_ctx.flexio_app);
	if (err) {
		printf("Failed to get Flex IO app\n");
		goto cleanup;
	}

	/* Create a Flex IO process.
	 * The flexio_app struct is passed to load the program.
	 * No process creation attributes are needed for this application (default outbox).
	 * Created SW struct will be returned through the given pointer.
	 */
	if (flexio_process_create(app_ctx.ibv_ctx, app_ctx.flexio_app, NULL, &app_fp)) {
		printf("Failed to create Flex IO process.\n");
		err = -1;
		goto cleanup;
	}

	/* Store the value of flexio_process in the structure for to pass it to the functions. */
	app_ctx.flexio_process = app_fp;

	/* Get the token for user debug access to the Flex IO process. */
	udbg_token = flexio_process_udbg_token_get(app_fp);

	/* If the token is 0, user debug access for the process is not allowed.
	 * If the token is not 0, the user can attach the FlexIO debugger to the process,
	 * set breakpoints, and debug the device application.
	 */
	if (udbg_token)
		printf("Use the token >>> %#lx <<< for debugging\n", udbg_token);

	/* Create a Flex IO message stream for process.
	 * Size of single message stream is MSG_HOST_BUFF_BSIZE.
	 * Working mode is synchronous.
	 * Level of debug in INFO.
	 * Transport mode - QP RC (possible alternatives - QP UC or QP UD)
	 * Output is stdout.
	 */
	stream_fattr.data_bsize = MSG_HOST_BUFF_BSIZE;
	stream_fattr.sync_mode = FLEXIO_MSG_DEV_SYNC_MODE_SYNC;
	stream_fattr.level = FLEXIO_MSG_DEV_INFO;
	stream_fattr.transport_mode = FLEXIO_MSG_TRANSPORT_QP_RC;

	if (flexio_msg_stream_create(app_fp, &stream_fattr, stdout, NULL,
				     &app_ctx.stream)) {
		printf("Failed to init device messaging environment, exiting App\n");
		err = -1;
		goto cleanup;
	}

	app_ctx.process_pd = flexio_process_get_pd(app_fp);
	app_ctx.process_uar = flexio_process_get_uar(app_fp);

    #ifdef HOSTBUF
	/* Create FlexIO window for DPA→host memory access (host buffer mode only). */
    if (flexio_window_create(app_fp, app_ctx.process_pd, &app_ctx.window)) {
        printf("Failed to create Flex IO window\n");
        err = -1;
        goto cleanup;
    }
    #endif

	/* Allocate per-thread context array. calloc ensures all fields start as zero/NULL. */
	app_ctx.threads = calloc(app_ctx.num_threads, sizeof(struct thread_ctx));
	if (!app_ctx.threads) {
		printf("Failed to allocate thread context array.\n");
		err = -1;
		goto cleanup;
	}

	/* Initialize all per-thread resources. */
	for (i = 0; i < app_ctx.num_threads; i++) {
		struct thread_ctx *t = &app_ctx.threads[i];

		t->thread_index    = (uint32_t)i;

		/* Create an event handler pinned to EU i (FLEXIO_AFFINITY_STRICT). */
		if (create_thread_event_handler(&app_ctx, t)) {
			printf("Failed to create event handler for thread %d.\n", i);
			err = -1;
			goto cleanup;
		}

		/* Create an SQ for this thread. */
		if (create_thread_sq(&app_ctx, t)) {
			printf("Failed to create SQ for thread %d.\n", i);
			err = -1;
			goto cleanup;
		}

		/* Create an RQ for this thread (RQ-CQ is linked to this thread's event handler). */
		if (create_thread_rq(&app_ctx, t)) {
			printf("Failed to create RQ for thread %d.\n", i);
			err = -1;
			goto cleanup;
		}

		/* Create steering rules matching SMAC = BASE_SMAC + i for this thread. */
		if (create_thread_steering_rules(&app_ctx, t, nic_mode)) {
			printf("Failed to create steering rules for thread %d.\n", i);
			err = -1;
			goto cleanup;
		}

		/* Copy queue descriptors and thread_index to DPA heap. */
		if (copy_thread_data_to_dpa(&app_ctx, t)) {
			printf("Failed to copy application data for thread %d.\n", i);
			err = -1;
			goto cleanup;
		}
	}

	printf("Ready to receive messages\n");

	/* Start all event handlers. Two-phase: create all resources first, then run.
	 * Event handlers in the running state may be invoked by an incoming CQE.
	 */
	for (i = 0; i < app_ctx.num_threads; i++) {
		struct thread_ctx *t = &app_ctx.threads[i];

		if (flexio_event_handler_run(t->pp_eh, t->app_data_daddr)) {
			printf("Failed to run event handler for thread %d.\n", i);
			err = -1;
			goto cleanup;
		}
	}

	/* Start host decompression observer (no-op when hostdecomp_enable == 0). */
    #if CQE_COMP==2
	if (hostdecomp_start(&hostdecomp_ctx, &app_ctx)) {
		printf("Failed to start hostdecomp observer\n");
		err = -1;
		goto cleanup;
	}
    #endif

	if (system_prompt(&app_ctx)) {
		printf("Failed to use system prompt");
		err = -1;
		goto cleanup;
	}

cleanup:
    #if CQE_COMP==2
	/* Stop the host decompression observer before tearing down hardware resources. */
	if (hostdecomp_stop(&hostdecomp_ctx)) {
		printf("Failed to stop hostdecomp observer\n");
		err = -1;
	}
    #endif
	/* Clean up flow is done in reverse order of creation as there's a reference system
	 * that won't allow destroying resources that has references to existing resources.
	 */

	if (app_ctx.threads) {
		/* Free DPA heap memory for all thread descriptors (reverse order). */
		for (i = app_ctx.num_threads - 1; i >= 0; i--) {
			struct thread_ctx *t = &app_ctx.threads[i];

			if (t->app_data_daddr &&
			    flexio_buf_dev_free(app_fp, t->app_data_daddr)) {
				printf("Failed to dealloc app data for thread %d\n", i);
				err = -1;
			}
		}

		/* Destroy steering rules (reverse order). */
		for (i = app_ctx.num_threads - 1; i >= 0; i--) {
			if (clean_up_thread_rules(&app_ctx.threads[i]))
				err = -1;
		}

		/* Destroy RQ resources first (reverse order).
		 * Must precede SQ cleanup so the DEVX UMEM for the host CQ ring is
		 * deregistered before the combined buffer (owned by the SQ side) is freed.
		 */
		for (i = app_ctx.num_threads - 1; i >= 0; i--) {
			if (clean_up_thread_rq(&app_ctx, &app_ctx.threads[i]))
				err = -1;
		}

		/* Destroy SQ resources (reverse order). */
		for (i = app_ctx.num_threads - 1; i >= 0; i--) {
			if (clean_up_thread_sq(&app_ctx, &app_ctx.threads[i]))
				err = -1;
		}

		/* Destroy event handlers (reverse order). */
		for (i = app_ctx.num_threads - 1; i >= 0; i--) {
			struct thread_ctx *t = &app_ctx.threads[i];

			if (t->pp_eh && flexio_event_handler_destroy(t->pp_eh)) {
				printf("Failed to destroy event handler for thread %d\n", i);
				err = -1;
			}
		}

		free(app_ctx.threads);
		app_ctx.threads = NULL;
	}

	/* Destroy FlexIO window if created */
	if (app_ctx.window && flexio_window_destroy(app_ctx.window)) {
		printf("Failed to destroy Flex IO window\n");
		err = -1;
	}

	/* Destroy message stream if created */
	if (app_fp && flexio_msg_stream_destroy(app_ctx.stream)) {
		printf("Failed to destroy device messaging environment\n");
		err = -1;
	}

	/* Destroy the Flex IO process */
	if (flexio_process_destroy(app_fp)) {
		printf("Failed to destroy process.\n");
		err = -1;
	}

	/* Close the IBV device */
	if (ibv_close_device(app_ctx.ibv_ctx)) {
		printf("Failed to close ibv context.\n");
		err = -1;
	}

	return err;
}
