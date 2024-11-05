/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2024 Marvell.
 */


#include "roc_api.h"
#include "roc_priv.h"

void
roc_ow_ipsec_inb_sa_init(struct roc_ow_ipsec_inb_sa *sa)
{
	size_t offset;

	memset(sa, 0, sizeof(struct roc_ow_ipsec_inb_sa));

	sa->w0.s.pkt_output = ROC_IE_OW_SA_PKT_OUTPUT_NO_FRAG;
	sa->w0.s.pkt_format = ROC_IE_OW_SA_PKT_FMT_META;
	sa->w0.s.pkind = ROC_IE_OW_CPT_PKIND;
	sa->w0.s.et_ovrwr = 1;
	sa->w2.s.l3hdr_on_err = 1;

	offset = offsetof(struct roc_ow_ipsec_inb_sa, ctx);
	sa->w0.s.hw_ctx_off = offset / ROC_CTX_UNIT_8B;
	sa->w0.s.ctx_push_size = sa->w0.s.hw_ctx_off + 1;
	sa->w0.s.ctx_size = ROC_IE_OW_CTX_ILEN;
	sa->w0.s.ctx_hdr_size = ROC_IE_OW_SA_CTX_HDR_SIZE;
	sa->w0.s.aop_valid = 1;
}

void
roc_ow_reass_inb_sa_init(struct roc_ow_ipsec_inb_sa *sa)
{
	size_t offset;

	memset(sa, 0, sizeof(struct roc_ow_ipsec_inb_sa));

	sa->w0.s.pkt_output = ROC_IE_OW_SA_PKT_OUTPUT_HW_BASED_DEFRAG;
	sa->w0.s.pkt_format = ROC_IE_OW_SA_PKT_FMT_META;
	sa->w0.s.pkind = ROC_IE_OW_CPT_PKIND;
	sa->w2.s.l3hdr_on_err = 1;
	sa->w2.s.valid = 1;
	sa->w2.s.dir = ROC_IE_SA_DIR_INBOUND;

	offset = offsetof(struct roc_ow_ipsec_inb_sa, ctx);
	sa->w0.s.hw_ctx_off = offset / ROC_CTX_UNIT_8B;
	sa->w0.s.ctx_push_size = sa->w0.s.hw_ctx_off + 1;
	sa->w0.s.ctx_size = ROC_IE_OW_CTX_ILEN;
	sa->w0.s.ctx_hdr_size = ROC_IE_OW_SA_CTX_HDR_SIZE;
	sa->w0.s.aop_valid = 1;
}

void
roc_ow_ipsec_outb_sa_init(struct roc_ow_ipsec_outb_sa *sa)
{
	size_t offset;

	memset(sa, 0, sizeof(struct roc_ow_ipsec_outb_sa));

	offset = offsetof(struct roc_ow_ipsec_outb_sa, ctx);
	sa->w0.s.ctx_push_size = (offset / ROC_CTX_UNIT_8B) + 1;
	sa->w0.s.ctx_size = ROC_IE_OW_CTX_ILEN;
	sa->w0.s.aop_valid = 1;
}
