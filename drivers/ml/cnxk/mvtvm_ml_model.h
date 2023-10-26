/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Marvell.
 */

#ifndef _MVTVM_ML_MODEL_H_
#define _MVTVM_ML_MODEL_H_

#include <tvmdp.h>

#include <rte_mldev.h>

#include "cnxk_ml_io.h"

/* Maximum number of objects per model */
#define ML_MVTVM_MODEL_OBJECT_MAX 3

/* Objects list */
extern char mvtvm_object_list[ML_MVTVM_MODEL_OBJECT_MAX][RTE_ML_STR_MAX];

/* Model object structure */
struct mvtvm_ml_model_object {
	/* Name */
	char name[RTE_ML_STR_MAX];

	/* Temporary buffer */
	uint8_t *buffer;

	/* Buffer size */
	int64_t size;
};

struct mvtvm_ml_model_data {
	/* Model metadata */
	struct tvmdp_model_metadata metadata;

	/* Model objects */
	struct tvmdp_model_object object;

	/* TVM runtime callbacks */
	struct tvmrt_glow_callback cb;

	/* Model I/O info */
	struct cnxk_ml_io_info info;
};

#endif /* _MVTVM_ML_MODEL_H_ */