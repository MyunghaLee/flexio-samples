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

/* Source file with functions for Flow Steering Rules tables */

#include <malloc.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <endian.h>

#include "flow_steering_utils.h"

enum matcher_criteria {
	MATCHER_CRITERIA_EMPTY = 0,
	MATCHER_CRITERIA_OUTER = 1 << 0,
	MATCHER_CRITERIA_MISC  = 1 << 1,
	MATCHER_CRITERIA_INNER = 1 << 2,
	MATCHER_CRITERIA_MISC2 = 1 << 3,
	MATCHER_CRITERIA_MISC3 = 1 << 4,
};

struct mlx5_ifc_dr_match_spec_bits {
	uint8_t smac_47_16[0x20];

	uint8_t smac_15_0[0x10];
	uint8_t ethertype[0x10];

	uint8_t dmac_47_16[0x20];

	uint8_t dmac_15_0[0x10];
	uint8_t first_prio[0x3];
	uint8_t first_cfi[0x1];
	uint8_t first_vid[0xc];

	uint8_t ip_protocol[0x8];
	uint8_t ip_dscp[0x6];
	uint8_t ip_ecn[0x2];
	uint8_t cvlan_tag[0x1];
	uint8_t svlan_tag[0x1];
	uint8_t frag[0x1];
	uint8_t ip_version[0x4];
	uint8_t tcp_flags[0x9];

	uint8_t tcp_sport[0x10];
	uint8_t tcp_dport[0x10];

	uint8_t reserved_at_c0[0x18];
	uint8_t ip_ttl_hoplimit[0x8];

	uint8_t udp_sport[0x10];
	uint8_t udp_dport[0x10];

	uint8_t src_ip_127_96[0x20];

	uint8_t src_ip_95_64[0x20];

	uint8_t src_ip_63_32[0x20];

	uint8_t src_ip_31_0[0x20];

	uint8_t dst_ip_127_96[0x20];

	uint8_t dst_ip_95_64[0x20];

	uint8_t dst_ip_63_32[0x20];

	uint8_t dst_ip_31_0[0x20];
};

/* Every usage of this value is in bytes */
#define MATCH_VAL_BSIZE 64

static struct flow_matcher
*create_flow_matcher_sw_steer_rx(struct ibv_context *ibv_ctx,
				 struct mlx5dv_flow_match_parameters *match_mask,
				 enum mlx5dv_dr_domain_type type)
{
	struct flow_matcher *flow_match;

	flow_match = (struct flow_matcher *)calloc(1, sizeof(*flow_match));
	assert(flow_match);

	/* SW steering table and matcher are not used for RX steering */
	flow_match->dr_table_sws = NULL;
	flow_match->dr_matcher_sws = NULL;

	flow_match->dr_domain = mlx5dv_dr_domain_create(ibv_ctx, type);
	if (!flow_match->dr_domain) {
		printf("Fail creating dr_domain (errno %d)\n", errno);
		goto error;
	}

	flow_match->dr_table_root = mlx5dv_dr_table_create(flow_match->dr_domain, 0);
	if (!flow_match->dr_table_root) {
		printf("Fail creating dr_table (errno %d)\n", errno);
		goto error;
	}

	flow_match->dr_matcher_root = mlx5dv_dr_matcher_create(flow_match->dr_table_root, 0,
							       MATCHER_CRITERIA_OUTER, match_mask);
	if (!flow_match->dr_matcher_root) {
		printf("Fail creating dr_matcher (errno %d)\n", errno);
		goto error;
	}
	return flow_match;

error:
	return NULL;
}

static struct flow_matcher
*create_flow_matcher_sw_steer_tx(struct ibv_context *ibv_ctx,
				 struct mlx5dv_flow_match_parameters *match_mask,
				 enum mlx5dv_dr_domain_type type)
{
	struct flow_matcher *flow_match;

	flow_match = (struct flow_matcher *)calloc(1, sizeof(*flow_match));
	assert(flow_match);

	flow_match->dr_domain = mlx5dv_dr_domain_create(ibv_ctx, type);
	if (!flow_match->dr_domain) {
		printf("Fail creating dr_domain (errno %d)\n", errno);
		goto error;
	}

	flow_match->dr_table_root = mlx5dv_dr_table_create(flow_match->dr_domain, 0);
	if (!flow_match->dr_table_root) {
		printf("Fail creating dr_table_root (errno %d)\n", errno);
		goto error;
	}

	flow_match->dr_matcher_root = mlx5dv_dr_matcher_create(flow_match->dr_table_root, 0,
							       MATCHER_CRITERIA_OUTER, match_mask);
	if (!flow_match->dr_matcher_root) {
		printf("Fail creating dr_matcher_root (errno %d)\n", errno);
		goto error;
	}

	flow_match->dr_table_sws = mlx5dv_dr_table_create(flow_match->dr_domain, 1);
	if (!flow_match->dr_table_sws) {
		printf("Fail creating dr_table_sws (errno %d)\n", errno);
		goto error;
	}

	flow_match->dr_matcher_sws = mlx5dv_dr_matcher_create(flow_match->dr_table_sws, 0,
							      MATCHER_CRITERIA_OUTER, match_mask);
	if (!flow_match->dr_matcher_sws) {
		printf("Fail creating dr_matcher_sws (errno %d)\n", errno);
		goto error;
	}

	return flow_match;

error:
	return NULL;
}

static struct flow_rule *create_flow_rule_rx(struct flow_matcher *flow_matcher,
					     struct mlx5dv_devx_obj *tir_obj,
					     struct mlx5dv_flow_match_parameters *match_value)
{
	struct mlx5dv_dr_action *actions[1];
	struct flow_rule *flow_rule;

	flow_rule = (struct flow_rule *)calloc(1, sizeof(*flow_rule));
	assert(flow_rule);

	flow_rule->action = mlx5dv_dr_action_create_dest_devx_tir(tir_obj);
	if (!flow_rule->action) {
		printf("Failed creating TIR action (errno %d).\n", errno);
		goto err_out;
	}
	actions[0] = flow_rule->action;

	flow_rule->dr_rule = mlx5dv_dr_rule_create(flow_matcher->dr_matcher_root, match_value, 1,
						   actions);
	if (!flow_rule->dr_rule) {
		printf("Fail creating dr_rule (errno %d).\n", errno);
		goto err_out;
	}

	return flow_rule;

err_out:
	if (flow_rule->action)
		mlx5dv_dr_action_destroy(flow_rule->action);
	free(flow_rule);
	return NULL;
}

static struct flow_rule *create_flow_rule_tx(struct flow_matcher *flow_matcher,
					     struct mlx5dv_flow_match_parameters *match_value)
{
	struct mlx5dv_dr_action *actions[1];
	struct flow_rule *flow_rule;

	flow_rule = (struct flow_rule *)calloc(1, sizeof(*flow_rule));
	assert(flow_rule);

	flow_rule->action = mlx5dv_dr_action_create_dest_vport(flow_matcher->dr_domain, 0xFFFF);
	if (!flow_rule->action) {
		printf("Failed creating dest vport action (errno %d).\n", errno);
		goto err_out;
	}
	actions[0] = flow_rule->action;

	flow_rule->dr_rule = mlx5dv_dr_rule_create(flow_matcher->dr_matcher_sws, match_value, 1,
						   actions);
	if (!flow_rule->dr_rule) {
		printf("Fail creating dr_rule (errno %d).\n", errno);
		goto err_out;
	}

	return flow_rule;

err_out:
	if (flow_rule->action)
		mlx5dv_dr_action_destroy(flow_rule->action);
	free(flow_rule);
	return NULL;
}

static struct flow_rule *create_flow_rule_tx_table(struct flow_matcher *flow_matcher,
						   struct mlx5dv_flow_match_parameters *match_value)
{
	struct mlx5dv_dr_action *actions[1];
	struct flow_rule *flow_rule;

	flow_rule = (struct flow_rule *)calloc(1, sizeof(*flow_rule));
	assert(flow_rule);

	flow_rule->action = mlx5dv_dr_action_create_dest_table(flow_matcher->dr_table_sws);
	if (!flow_rule->action) {
		printf("Failed creating dest SWS table action (errno %d).\n", errno);
		goto err_out;
	}
	actions[0] = flow_rule->action;

	flow_rule->dr_rule = mlx5dv_dr_rule_create(flow_matcher->dr_matcher_root, match_value, 1,
						   actions);
	if (!flow_rule->dr_rule) {
		printf("Fail creating dr_rule (errno %d).\n", errno);
		goto err_out;
	}

	return flow_rule;

err_out:
	if (flow_rule->action)
		mlx5dv_dr_action_destroy(flow_rule->action);
	free(flow_rule);
	return NULL;
}

struct flow_matcher *create_matcher_rx(struct ibv_context *ibv_ctx)
{
	struct mlx5dv_flow_match_parameters *match_mask;
	struct flow_matcher *matcher;
	int match_mask_size;

	/* mask & match value */
	match_mask_size = sizeof(*match_mask) + MATCH_VAL_BSIZE;
	match_mask = (struct mlx5dv_flow_match_parameters *)calloc(1, match_mask_size);
	assert(match_mask);

	match_mask->match_sz = MATCH_VAL_BSIZE;
	DEVX_SET(dr_match_spec, match_mask->match_buf, smac_47_16, 0xffffffff);
	DEVX_SET(dr_match_spec, match_mask->match_buf, smac_15_0, 0xffff);

	matcher = create_flow_matcher_sw_steer_rx(ibv_ctx, match_mask,
						  MLX5DV_DR_DOMAIN_TYPE_NIC_RX);
	free(match_mask);

	return matcher;
}

struct flow_matcher *create_matcher_tx(struct ibv_context *ibv_ctx)
{
	struct mlx5dv_flow_match_parameters *match_mask;
	struct flow_matcher *matcher;
	int match_mask_size;

	/* mask & match value */
	match_mask_size = sizeof(*match_mask) + MATCH_VAL_BSIZE;
	match_mask = (struct mlx5dv_flow_match_parameters *)calloc(1, match_mask_size);
	assert(match_mask);

	match_mask->match_sz = MATCH_VAL_BSIZE;
	DEVX_SET(dr_match_spec, match_mask->match_buf, dmac_47_16, 0xffffffff);
	DEVX_SET(dr_match_spec, match_mask->match_buf, dmac_15_0, 0xffff);
	matcher = create_flow_matcher_sw_steer_tx(ibv_ctx, match_mask, MLX5DV_DR_DOMAIN_TYPE_FDB);
	free(match_mask);

	return matcher;
}

struct flow_rule *create_rule_rx_mac_match(struct flow_matcher *flow_match,
					   struct mlx5dv_devx_obj *tir_obj, uint64_t smac)
{
	struct mlx5dv_flow_match_parameters *match_value;
	struct flow_rule *flow_rule;
	int match_value_size;

	/* mask & match value */
	match_value_size = sizeof(*match_value) + MATCH_VAL_BSIZE;
	match_value = (struct mlx5dv_flow_match_parameters *)calloc(1, match_value_size);
	assert(match_value);

	match_value->match_sz = MATCH_VAL_BSIZE;
	DEVX_SET(dr_match_spec, match_value->match_buf, smac_47_16, smac >> 16);
	DEVX_SET(dr_match_spec, match_value->match_buf, smac_15_0, smac % (1 << 16));
	flow_rule = create_flow_rule_rx(flow_match, tir_obj, match_value);
	free(match_value);

	return flow_rule;
}

struct flow_rule *create_rule_tx_fwd_to_vport(struct flow_matcher *flow_match, uint64_t dmac)
{
	struct mlx5dv_flow_match_parameters *match_value;
	struct flow_rule *flow_rule;
	int match_value_size;

	/* mask & match value */
	match_value_size = sizeof(*match_value) + MATCH_VAL_BSIZE;
	match_value = (struct mlx5dv_flow_match_parameters *)calloc(1, match_value_size);
	assert(match_value);

	match_value->match_sz = MATCH_VAL_BSIZE;
	DEVX_SET(dr_match_spec, match_value->match_buf, dmac_47_16, dmac >> 16);
	DEVX_SET(dr_match_spec, match_value->match_buf, dmac_15_0, dmac % (1 << 16));
	flow_rule = create_flow_rule_tx(flow_match, match_value);
	free(match_value);

	return flow_rule;
}

struct flow_rule *create_rule_tx_fwd_to_sws_table(struct flow_matcher *flow_match, uint64_t dmac)
{
	struct mlx5dv_flow_match_parameters *match_value;
	struct flow_rule *flow_rule;
	int match_value_size;

	/* mask & match value */
	match_value_size = sizeof(*match_value) + MATCH_VAL_BSIZE;
	match_value = (struct mlx5dv_flow_match_parameters *)calloc(1, match_value_size);
	assert(match_value);

	match_value->match_sz = MATCH_VAL_BSIZE;
	DEVX_SET(dr_match_spec, match_value->match_buf, dmac_47_16, dmac >> 16);
	DEVX_SET(dr_match_spec, match_value->match_buf, dmac_15_0, dmac % (1 << 16));
	flow_rule = create_flow_rule_tx_table(flow_match, match_value);
	free(match_value);

	return flow_rule;
}

int destroy_matcher(struct flow_matcher *matcher)
{
	int err;

	err = mlx5dv_dr_matcher_destroy(matcher->dr_matcher_root);
	if (err)
		return err;

	err = mlx5dv_dr_table_destroy(matcher->dr_table_root);
	if (err)
		return err;

	if (matcher->dr_matcher_sws) {
		err = mlx5dv_dr_matcher_destroy(matcher->dr_matcher_sws);
		if (err)
			return err;
	}

	if (matcher->dr_table_sws) {
		err = mlx5dv_dr_table_destroy(matcher->dr_table_sws);
		if (err)
			return err;
	}

	err = mlx5dv_dr_domain_destroy(matcher->dr_domain);
	if (err)
		return err;

	free(matcher);

	return 0;
}

int destroy_rule(struct flow_rule *rule)
{
	int err;

	err = mlx5dv_dr_rule_destroy(rule->dr_rule);
	if (err)
		return err;

	err = mlx5dv_dr_action_destroy(rule->action);
	if (err)
		return err;

	free(rule);

	return 0;
}

/* ---------------------------------------------------------------------------
 * RSS flow steering helpers
 *
 * DEVX command buffers use big-endian 32-bit words.  The DEVX "1 byte per
 * bit" struct convention means sizeof(struct mlx5_ifc_foo_bits) == number of
 * bits in the hardware struct.  All offsets below are derived from the kernel
 * mlx5_ifc.h bit layouts:
 *
 *   ALLOC_TRANSPORT_DOMAIN_IN  (opcode 0x816): 128 bits = 4 dwords
 *   ALLOC_TRANSPORT_DOMAIN_OUT              : 128 bits = 4 dwords
 *     transport_domain at out-dword[2] bits[23:0]
 *
 *   CREATE_RQT_IN  (opcode 0x916):
 *     32-byte fixed header + 240-byte rqtc fixed part + num_rqs*4 bytes
 *     rqt_max_size  at rqtc-dword[5]  bits[15:0]  => buf-dword[13]
 *     rqt_actual_size at rqtc-dword[6] bits[15:0] => buf-dword[14]
 *     rq_num[i] at rqtc-dword[68+i]   bits[23:0] => buf-dword[68+i]
 *   CREATE_RQT_OUT:
 *     rqtn at out-dword[2] bits[23:0]
 *
 *   CREATE_TIR_IN  (opcode 0x900):
 *     32-byte fixed header + 240-byte tirc = 272 bytes = 68 dwords
 *     tirc starts at buf-dword[8]:
 *       disp_type        at tirc-dword[1]  bits[31:28] => buf-dword[9]
 *       rx_hash_symmetric at tirc-dword[8] bit[31]     => buf-dword[16]
 *       indirect_table   at tirc-dword[8]  bits[23:0]  => buf-dword[16]
 *       rx_hash_fn       at tirc-dword[9]  bits[31:28] => buf-dword[17]
 *       transport_domain at tirc-dword[9]  bits[23:0]  => buf-dword[17]
 *       rx_hash_toeplitz_key (40 B)        starts at   => buf-dword[18]
 *       rx_hash_field_selector_outer       at          => buf-dword[28]
 *         l3_prot_type bit[31], l4_prot_type bit[30], selected_fields bits[29:0]
 *   CREATE_TIR_OUT:
 *     tirn at out-dword[2] bits[23:0]
 * ---------------------------------------------------------------------------
 */

/* Standard 40-byte Toeplitz RSS hash key (same as Linux/DPDK default). */
static const uint8_t rss_hash_key[40] = {
	0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
	0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
	0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
	0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
	0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
};

/* Allocate a transport domain via DEVX.  Returns the devx object and stores
 * the hardware transport_domain number in *tdn_out.  Returns NULL on error.
 */
static struct mlx5dv_devx_obj *alloc_transport_domain(struct ibv_context *ibv_ctx,
						       uint32_t *tdn_out)
{
	uint32_t in[4]  = {0};
	uint32_t out[4] = {0};
	struct mlx5dv_devx_obj *obj;

	in[0] = htobe32(0x816u << 16);  /* opcode ALLOC_TRANSPORT_DOMAIN */

	obj = mlx5dv_devx_obj_create(ibv_ctx, in, sizeof(in), out, sizeof(out));
	if (!obj) {
		printf("Failed to allocate transport domain (errno %d)\n", errno);
		return NULL;
	}

	*tdn_out = be32toh(out[2]) & 0x00ffffffu;
	return obj;
}

/* Create an RQT containing the given RQ numbers via DEVX.
 * Returns the devx object and stores the hardware rqtn in *rqtn_out.
 */
static struct mlx5dv_devx_obj *create_rqt(struct ibv_context *ibv_ctx,
					   uint32_t *rq_nums, int num_rqs,
					   uint32_t *rqtn_out)
{
	/* Buffer: 32-byte header + 240-byte rqtc fixed + num_rqs*4 bytes entries */
	size_t inlen = 32 + 240 + (size_t)num_rqs * 4;
	uint32_t *in  = calloc(1, inlen);
	uint32_t  out[4] = {0};
	struct mlx5dv_devx_obj *obj;

	if (!in) {
		printf("Failed to allocate RQT command buffer\n");
		return NULL;
	}

	in[0]  = htobe32(0x916u << 16);          /* opcode CREATE_RQT */
	in[13] = htobe32((uint32_t)num_rqs);      /* rqt_max_size  bits[15:0] */
	in[14] = htobe32((uint32_t)num_rqs);      /* rqt_actual_size bits[15:0] */
	for (int i = 0; i < num_rqs; i++)
		in[68 + i] = htobe32(rq_nums[i] & 0x00ffffffu); /* rq_num[i] bits[23:0] */

	obj = mlx5dv_devx_obj_create(ibv_ctx, in, inlen, out, sizeof(out));
	free(in);
	if (!obj) {
		printf("Failed to create RQT (errno %d)\n", errno);
		return NULL;
	}

	*rqtn_out = be32toh(out[2]) & 0x00ffffffu;
	return obj;
}

/* Create an indirect (RSS) TIR pointing to rqtn, using Toeplitz hash over
 * {src_ip, dst_ip, l4_sport, l4_dport}.  Returns the devx object on success.
 */
static struct mlx5dv_devx_obj *create_indirect_tir(struct ibv_context *ibv_ctx,
						    uint32_t rqtn, uint32_t tdn)
{
	/* CREATE_TIR_IN: 32-byte header + 240-byte tirc = 272 bytes = 68 dwords */
	uint32_t in[68]  = {0};
	uint32_t out[4]  = {0};

	in[0]  = htobe32(0x900u << 16);  /* opcode CREATE_TIR */

	/* tirc starts at in[8]:
	 *   dword 1 (in[9]):  disp_type=1 (indirect) at bits[31:28]
	 *   dword 8 (in[16]): rx_hash_symmetric=1 at bit[31], indirect_table at bits[23:0]
	 *   dword 9 (in[17]): rx_hash_fn=2 (Toeplitz) at bits[31:28], transport_domain bits[23:0]
	 *   dwords 10-19 (in[18..27]): rx_hash_toeplitz_key (40 bytes)
	 *   dword 20 (in[28]): rx_hash_field_selector_outer
	 *     bit[31]=l3_prot_type(0=IPv4), bit[30]=l4_prot_type(0=TCP),
	 *     bits[29:0]=selected_fields (SRC_IP|DST_IP|L4_SPORT|L4_DPORT = 0xF)
	 */
	in[9]  = htobe32(1u << 28);                          /* disp_type = INDIRECT */
	in[16] = htobe32((1u << 31) | (rqtn & 0x00ffffffu)); /* symmetric=1, indirect_table */
	in[17] = htobe32((2u << 28) | (tdn  & 0x00ffffffu)); /* rx_hash_fn=TOEPLITZ, TD */

	/* Copy Toeplitz key as big-endian dwords. */
	memcpy(&in[18], rss_hash_key, sizeof(rss_hash_key));
	for (int i = 0; i < 10; i++)
		in[18 + i] = htobe32(be32toh(in[18 + i]));

	/* rx_hash_field_selector_outer: hash on src+dst IP and L4 ports. */
	in[28] = htobe32(0x0000000Fu);

	struct mlx5dv_devx_obj *obj =
		mlx5dv_devx_obj_create(ibv_ctx, in, sizeof(in), out, sizeof(out));
	if (!obj) {
		printf("Failed to create indirect TIR (errno %d)\n", errno);
		return NULL;
	}
	return obj;
}

struct rss_flow_resources *create_rss_steering(struct ibv_context *ibv_ctx,
					       uint32_t *rq_nums, int num_rqs,
					       uint64_t smac, int nic_mode)
{
	struct rss_flow_resources *rss;
	uint32_t tdn = 0, rqtn = 0;

	rss = calloc(1, sizeof(*rss));
	if (!rss)
		return NULL;

	/* Allocate a transport domain for the RSS TIR. */
	rss->td = alloc_transport_domain(ibv_ctx, &tdn);
	if (!rss->td)
		goto error;

	/* Create RQT with all thread RQ numbers. */
	rss->rqt = create_rqt(ibv_ctx, rq_nums, num_rqs, &rqtn);
	if (!rss->rqt)
		goto error;

	/* Create indirect TIR pointing to the RQT. */
	rss->tir = create_indirect_tir(ibv_ctx, rqtn, tdn);
	if (!rss->tir)
		goto error;

	/* Single RX flow matcher + rule matching smac → RSS TIR. */
	rss->rx_matcher = create_matcher_rx(ibv_ctx);
	if (!rss->rx_matcher)
		goto error;

	rss->rx_rule = create_rule_rx_mac_match(rss->rx_matcher, rss->tir, smac);
	if (!rss->rx_rule)
		goto error;

	/* Single TX flow matcher + rules (DPU mode only). */
	if (!nic_mode) {
		rss->tx_matcher = create_matcher_tx(ibv_ctx);
		if (!rss->tx_matcher)
			goto error;

		rss->tx_rule_table = create_rule_tx_fwd_to_sws_table(rss->tx_matcher, smac);
		if (!rss->tx_rule_table)
			goto error;

		rss->tx_rule_vport = create_rule_tx_fwd_to_vport(rss->tx_matcher, smac);
		if (!rss->tx_rule_vport)
			goto error;
	}

	return rss;

error:
	destroy_rss_steering(rss);
	return NULL;
}

int destroy_rss_steering(struct rss_flow_resources *rss)
{
	int err = 0;

	if (!rss)
		return 0;

	if (rss->tx_rule_vport && destroy_rule(rss->tx_rule_vport)) {
		printf("Failed to destroy RSS TX rule vport\n");
		err = -1;
	}
	if (rss->tx_rule_table && destroy_rule(rss->tx_rule_table)) {
		printf("Failed to destroy RSS TX rule table\n");
		err = -1;
	}
	if (rss->tx_matcher && destroy_matcher(rss->tx_matcher)) {
		printf("Failed to destroy RSS TX matcher\n");
		err = -1;
	}
	if (rss->rx_rule && destroy_rule(rss->rx_rule)) {
		printf("Failed to destroy RSS RX rule\n");
		err = -1;
	}
	if (rss->rx_matcher && destroy_matcher(rss->rx_matcher)) {
		printf("Failed to destroy RSS RX matcher\n");
		err = -1;
	}
	if (rss->tir && mlx5dv_devx_obj_destroy(rss->tir)) {
		printf("Failed to destroy RSS TIR (errno %d)\n", errno);
		err = -1;
	}
	if (rss->rqt && mlx5dv_devx_obj_destroy(rss->rqt)) {
		printf("Failed to destroy RSS RQT (errno %d)\n", errno);
		err = -1;
	}
	if (rss->td && mlx5dv_devx_obj_destroy(rss->td)) {
		printf("Failed to destroy RSS TD (errno %d)\n", errno);
		err = -1;
	}
	free(rss);
	return err;
}
