/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */
#ifndef __CNXK_RTE_FLOW_H__
#define __CNXK_RTE_FLOW_H__

#include <rte_flow_driver.h>
#include <rte_malloc.h>

#include "cnxk_ethdev.h"
#include "roc_api.h"
#include "roc_npc_priv.h"

struct cnxk_rte_flow_term_info {
	uint16_t item_type;
	uint16_t item_size;
};

struct roc_npc_flow *cnxk_flow_create(struct rte_eth_dev *dev,
				      const struct rte_flow_attr *attr,
				      const struct rte_flow_item pattern[],
				      const struct rte_flow_action actions[],
				      struct rte_flow_error *error);
int cnxk_flow_destroy(struct rte_eth_dev *dev, struct roc_npc_flow *flow,
		      struct rte_flow_error *error);

struct roc_npc_flow *cnxk_flow_create_common(struct rte_eth_dev *eth_dev,
					     const struct rte_flow_attr *attr,
					     const struct rte_flow_item pattern[],
					     const struct rte_flow_action actions[],
					     struct rte_flow_error *error, bool is_rep);
int cnxk_flow_validate_common(struct rte_eth_dev *eth_dev, const struct rte_flow_attr *attr,
			      const struct rte_flow_item pattern[],
			      const struct rte_flow_action actions[], struct rte_flow_error *error,
			      bool is_rep);
int cnxk_flow_destroy_common(struct rte_eth_dev *eth_dev, struct roc_npc_flow *flow,
			     struct rte_flow_error *error, bool is_rep);
int cnxk_flow_flush_common(struct rte_eth_dev *eth_dev, struct rte_flow_error *error, bool is_rep);
int cnxk_flow_query_common(struct rte_eth_dev *eth_dev, struct rte_flow *flow,
			   const struct rte_flow_action *action, void *data,
			   struct rte_flow_error *error, bool is_rep);
int cnxk_flow_dev_dump_common(struct rte_eth_dev *eth_dev, struct rte_flow *flow, FILE *file,
			      struct rte_flow_error *error, bool is_rep);

#endif /* __CNXK_RTE_FLOW_H__ */
