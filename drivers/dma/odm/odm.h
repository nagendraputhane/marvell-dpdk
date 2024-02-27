/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2024 Marvell.
 */

#ifndef _ODM_H_
#define _ODM_H_

#include <rte_log.h>

extern int odm_logtype;

#define odm_err(fmt, args...)                                                                      \
	rte_log(RTE_LOG_ERR, odm_logtype, "%s(): %u " fmt "\n", __func__, __LINE__, ##args)
#define odm_info(fmt, args...)                                                                     \
	rte_log(RTE_LOG_INFO, odm_logtype, "%s(): %u " fmt "\n", __func__, __LINE__, ##args)

struct odm_dev {
	struct rte_pci_device *pci_dev;
	uint8_t *rbase;
	uint16_t vfid;
	uint8_t max_qs;
	uint8_t num_qs;
} __rte_cache_aligned;

#endif /* _ODM_H_ */
