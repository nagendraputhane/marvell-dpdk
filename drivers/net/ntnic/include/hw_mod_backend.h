/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _HW_MOD_BACKEND_H_
#define _HW_MOD_BACKEND_H_

#include <stdbool.h>

#include "ntlog.h"

#include "hw_mod_cat_v18.h"
#include "hw_mod_cat_v21.h"
#include "hw_mod_flm_v25.h"
#include "hw_mod_km_v7.h"
#include "hw_mod_qsl_v7.h"
#include "hw_mod_pdb_v9.h"
#include "hw_mod_slc_lr_v2.h"
#include "hw_mod_hsh_v5.h"
#include "hw_mod_tpe_v3.h"

#define MAX_PHYS_ADAPTERS 8

#define VER_MAJOR(ver) (((ver) >> 16) & 0xffff)
#define VER_MINOR(ver) ((ver) & 0xffff)

struct flow_api_backend_s;
struct common_func_s;

void *callocate_mod(struct common_func_s *mod, int sets, ...);
void zero_module_cache(struct common_func_s *mod);

#define ALL_ENTRIES -1000
#define ALL_BANK_ENTRIES -1001

#define INDEX_TOO_LARGE (-2)
#define INDEX_TOO_LARGE_LOG NT_LOG(INF, FILTER, "ERROR:%s: Index too large", __func__)

#define WORD_OFF_TOO_LARGE (-3)
#define WORD_OFF_TOO_LARGE_LOG NT_LOG(INF, FILTER, "ERROR:%s: Word offset too large", __func__)

#define UNSUP_FIELD (-5)
#define UNSUP_FIELD_LOG                                                         \
	NT_LOG(INF, FILTER, "ERROR:%s: Unsupported field in NIC module", __func__)

#define UNSUP_VER (-4)
#define UNSUP_VER_LOG                                                                       \
	NT_LOG(INF, FILTER, "ERROR:%s: Unsupported NIC module: %s ver %i.%i", __func__, _MOD_, \
		VER_MAJOR(_VER_), VER_MINOR(_VER_))

#define COUNT_ERROR (-4)
#define COUNT_ERROR_LOG(_RESOURCE_)                                                         \
	NT_LOG(INF, FILTER,                                                                      \
		"ERROR:%s: Insufficient resource [ %s ] : NIC module: %s ver %i.%i", __func__,  \
		#_RESOURCE_, _MOD_, VER_MAJOR(_VER_), VER_MINOR(_VER_))                          \

#define NOT_FOUND 0xffffffff

enum {
	EXTRA_INDEXES
};

#define GET(cached_val, val) ({ *(val) = *(cached_val); })

#define SET(cached_val, val) ({ *(cached_val) = *(val); })

#define GET_SET(cached_val, val)                                                                  \
	do {                                                                                      \
		uint32_t *temp_val = (val);                                                       \
		typeof(cached_val) *temp_cached_val = &(cached_val);                          \
		if (get)                                                                          \
			GET(temp_cached_val, temp_val);                                           \
		else                                                                              \
			SET(temp_cached_val, temp_val);                                           \
	} while (0)

#define GET_SIGNED(cached_val, val) ({ *(val) = (uint32_t)(*(cached_val)); })

#define SET_SIGNED(cached_val, val) ({ *(cached_val) = (int32_t)(*(val)); })

#define GET_SET_SIGNED(cached_val, val)                                                           \
	do {                                                                                      \
		uint32_t *temp_val = (val);                                                       \
		typeof(cached_val) *temp_cached_val = &(cached_val);                          \
		if (get)                                                                          \
			GET_SIGNED(temp_cached_val, temp_val);                                    \
		else                                                                              \
			SET_SIGNED(temp_cached_val, temp_val);                                    \
	} while (0)

#define FIND_EQUAL_INDEX(be_module_reg, type, idx, start, nb_elements)                            \
	do {                                                                                      \
		typeof(be_module_reg) *temp_be_module =                                       \
			(typeof(be_module_reg) *)be_module_reg;                               \
		typeof(idx) tmp_idx = (idx);                                                  \
		typeof(nb_elements) tmp_nb_elements = (nb_elements);                          \
		unsigned int start_idx = (unsigned int)(start);                                   \
		*value = NOT_FOUND;                                                               \
		for (unsigned int i = start_idx; i < tmp_nb_elements; i++) {                      \
			if ((unsigned int)(tmp_idx) == i)                                         \
				continue;                                                         \
			if (memcmp(&temp_be_module[tmp_idx], &temp_be_module[i], sizeof(type)) == \
			    0) {                                                                  \
				*value = i;                                                       \
				break;                                                            \
			}                                                                         \
		}                                                                                 \
	} while (0)

#define DO_COMPARE_INDEXS(be_module_reg, type, idx, cmp_idx)                                      \
	do {                                                                                      \
		typeof(be_module_reg) *temp_be_module = &(be_module_reg);                     \
		typeof(idx) tmp_idx = (idx);                                                  \
		typeof(cmp_idx) tmp_cmp_idx = (cmp_idx);                                      \
		if ((unsigned int)(tmp_idx) != (unsigned int)(tmp_cmp_idx)) {                     \
			(void)memcmp(temp_be_module + tmp_idx, &temp_be_module[tmp_cmp_idx],      \
				     sizeof(type));                                               \
		}                                                                                 \
	} while (0)

enum km_flm_if_select_e {
	KM_FLM_IF_FIRST = 0,
	KM_FLM_IF_SECOND = 1
};

#define FIELD_START_INDEX 100

#define COMMON_FUNC_INFO_S                                                                        \
	int ver;                                                                                  \
	void *base;                                                                               \
	unsigned int alloced_size;                                                                \
	int debug

struct common_func_s {
	COMMON_FUNC_INFO_S;
};

struct cat_func_s {
	COMMON_FUNC_INFO_S;
	uint32_t nb_cat_funcs;
	uint32_t nb_flow_types;
	uint32_t nb_pm_ext;
	uint32_t nb_len;
	uint32_t kcc_size;
	uint32_t cts_num;
	uint32_t kcc_banks;
	uint32_t kcc_id_bit_size;
	uint32_t kcc_records;
	uint32_t km_if_count;
	int32_t km_if_m0;
	int32_t km_if_m1;

	union {
		struct hw_mod_cat_v18_s v18;
		struct hw_mod_cat_v21_s v21;
	};
};
enum hw_cat_e {
	/*
	 * functions initial CAT v18
	 */
	/* 00 */ HW_CAT_CFN_SET_ALL_DEFAULTS = 0,
	/* 01 */ HW_CAT_CFN_PRESET_ALL,
	/* 02 */ HW_CAT_CFN_COMPARE,
	/* 03 */ HW_CAT_CFN_FIND,
	/* 04 */ HW_CAT_CFN_COPY_FROM,
	/* 05 */ HW_CAT_COT_PRESET_ALL,
	/* 06 */ HW_CAT_COT_COMPARE,
	/* 07 */ HW_CAT_COT_FIND,
	/* 08 */ HW_CAT_COT_COPY_FROM,
	/* fields */
	/* 00 */ HW_CAT_CFN_ENABLE = FIELD_START_INDEX,
	/* 01 */ HW_CAT_CFN_INV,
	/* 02 */ HW_CAT_CFN_PTC_INV,
	/* 03 */ HW_CAT_CFN_PTC_ISL,
	/* 04 */ HW_CAT_CFN_PTC_CFP,
	/* 05 */ HW_CAT_CFN_PTC_MAC,
	/* 06 */ HW_CAT_CFN_PTC_L2,
	/* 07 */ HW_CAT_CFN_PTC_VNTAG,
	/* 08 */ HW_CAT_CFN_PTC_VLAN,
	/* 09 */ HW_CAT_CFN_PTC_MPLS,
	/* 10 */ HW_CAT_CFN_PTC_L3,
	/* 11 */ HW_CAT_CFN_PTC_FRAG,
	/* 12 */ HW_CAT_CFN_PTC_IP_PROT,
	/* 13 */ HW_CAT_CFN_PTC_L4,
	/* 14 */ HW_CAT_CFN_PTC_TUNNEL,
	/* 15 */ HW_CAT_CFN_PTC_TNL_L2,
	/* 16 */ HW_CAT_CFN_PTC_TNL_VLAN,
	/* 17 */ HW_CAT_CFN_PTC_TNL_MPLS,
	/* 18 */ HW_CAT_CFN_PTC_TNL_L3,
	/* 19 */ HW_CAT_CFN_PTC_TNL_FRAG,
	/* 20 */ HW_CAT_CFN_PTC_TNL_IP_PROT,
	/* 21 */ HW_CAT_CFN_PTC_TNL_L4,
	/* 22 */ HW_CAT_CFN_ERR_INV,
	/* 23 */ HW_CAT_CFN_ERR_CV,
	/* 24 */ HW_CAT_CFN_ERR_FCS,
	/* 25 */ HW_CAT_CFN_ERR_TRUNC,
	/* 26 */ HW_CAT_CFN_ERR_L3_CS,
	/* 27 */ HW_CAT_CFN_ERR_L4_CS,
	/* 28 */ HW_CAT_CFN_MAC_PORT,
	/* 29 */ HW_CAT_CFN_PM_CMP,
	/* 30 */ HW_CAT_CFN_PM_DCT,
	/* 31 */ HW_CAT_CFN_PM_EXT_INV,
	/* 32 */ HW_CAT_CFN_PM_CMB,
	/* 33 */ HW_CAT_CFN_PM_AND_INV,
	/* 34 */ HW_CAT_CFN_PM_OR_INV,
	/* 35 */ HW_CAT_CFN_PM_INV,
	/* 36 */ HW_CAT_CFN_LC,
	/* 37 */ HW_CAT_CFN_LC_INV,
	/* 38 */ HW_CAT_CFN_KM0_OR,
	/* 39 */ HW_CAT_CFN_KM1_OR,
	/* 40 */ HW_CAT_KCE_ENABLE_BM,
	/* 41 */ HW_CAT_KCS_CATEGORY,
	/* 42 */ HW_CAT_FTE_ENABLE_BM,
	/* 43 */ HW_CAT_CTE_ENABLE_BM,
	/* 44 */ HW_CAT_CTS_CAT_A,
	/* 45 */ HW_CAT_CTS_CAT_B,
	/* 46 */ HW_CAT_COT_COLOR,
	/* 47 */ HW_CAT_COT_KM,
	/* 48 */ HW_CAT_CCT_COLOR,
	/* 49 */ HW_CAT_CCT_KM,
	/* 50 */ HW_CAT_KCC_KEY,
	/* 51 */ HW_CAT_KCC_CATEGORY,
	/* 52 */ HW_CAT_KCC_ID,
	/* 53 */ HW_CAT_EXO_DYN,
	/* 54 */ HW_CAT_EXO_OFS,
	/* 55 */ HW_CAT_RCK_DATA,
	/* 56 */ HW_CAT_LEN_LOWER,
	/* 57 */ HW_CAT_LEN_UPPER,
	/* 58 */ HW_CAT_LEN_DYN1,
	/* 59 */ HW_CAT_LEN_DYN2,
	/* 60 */ HW_CAT_LEN_INV,
	/* 61 */ HW_CAT_CFN_ERR_TNL_L3_CS,
	/* 62 */ HW_CAT_CFN_ERR_TNL_L4_CS,
	/* 63 */ HW_CAT_CFN_ERR_TTL_EXP,
	/* 64 */ HW_CAT_CFN_ERR_TNL_TTL_EXP,
};

bool hw_mod_cat_present(struct flow_api_backend_s *be);
int hw_mod_cat_alloc(struct flow_api_backend_s *be);
void hw_mod_cat_free(struct flow_api_backend_s *be);
int hw_mod_cat_reset(struct flow_api_backend_s *be);
int hw_mod_cat_cfn_flush(struct flow_api_backend_s *be, int start_idx, int count);
int hw_mod_cat_cfn_set(struct flow_api_backend_s *be, enum hw_cat_e field, int index, int word_off,
	uint32_t value);

int hw_mod_cat_cte_flush(struct flow_api_backend_s *be, int start_idx, int count);
int hw_mod_cat_cts_flush(struct flow_api_backend_s *be, int start_idx, int count);
int hw_mod_cat_cot_flush(struct flow_api_backend_s *be, int start_idx, int count);
int hw_mod_cat_cct_flush(struct flow_api_backend_s *be, int start_idx, int count);
int hw_mod_cat_kcc_flush(struct flow_api_backend_s *be, int start_idx, int count);

int hw_mod_cat_exo_flush(struct flow_api_backend_s *be, int start_idx, int count);
int hw_mod_cat_rck_flush(struct flow_api_backend_s *be, int start_idx, int count);
int hw_mod_cat_len_flush(struct flow_api_backend_s *be, int start_idx, int count);

struct km_func_s {
	COMMON_FUNC_INFO_S;
	uint32_t nb_categories;
	uint32_t nb_cam_banks;
	uint32_t nb_cam_record_words;
	uint32_t nb_cam_records;
	uint32_t nb_tcam_banks;
	uint32_t nb_tcam_bank_width;
	/* not read from backend, but rather set using version */
	uint32_t nb_km_rcp_mask_a_word_size;
	/* --- || --- */
	uint32_t nb_km_rcp_mask_b_word_size;
	union {
		struct hw_mod_km_v7_s v7;
	};
};
enum hw_km_e {
	/* functions */
	HW_KM_RCP_PRESET_ALL = 0,
	HW_KM_CAM_PRESET_ALL,
	/* to sync and reset hw with cache - force write all entries in a bank */
	HW_KM_TCAM_BANK_RESET,
	/* fields */
	HW_KM_RCP_QW0_DYN = FIELD_START_INDEX,
	HW_KM_RCP_QW0_OFS,
	HW_KM_RCP_QW0_SEL_A,
	HW_KM_RCP_QW0_SEL_B,
	HW_KM_RCP_QW4_DYN,
	HW_KM_RCP_QW4_OFS,
	HW_KM_RCP_QW4_SEL_A,
	HW_KM_RCP_QW4_SEL_B,
	HW_KM_RCP_DW8_DYN,
	HW_KM_RCP_DW8_OFS,
	HW_KM_RCP_DW8_SEL_A,
	HW_KM_RCP_DW8_SEL_B,
	HW_KM_RCP_DW10_DYN,
	HW_KM_RCP_DW10_OFS,
	HW_KM_RCP_DW10_SEL_A,
	HW_KM_RCP_DW10_SEL_B,
	HW_KM_RCP_SWX_CCH,
	HW_KM_RCP_SWX_SEL_A,
	HW_KM_RCP_SWX_SEL_B,
	HW_KM_RCP_MASK_A,
	HW_KM_RCP_MASK_B,
	HW_KM_RCP_DUAL,
	HW_KM_RCP_PAIRED,
	HW_KM_RCP_EL_A,
	HW_KM_RCP_EL_B,
	HW_KM_RCP_INFO_A,
	HW_KM_RCP_INFO_B,
	HW_KM_RCP_FTM_A,
	HW_KM_RCP_FTM_B,
	HW_KM_RCP_BANK_A,
	HW_KM_RCP_BANK_B,
	HW_KM_RCP_KL_A,
	HW_KM_RCP_KL_B,
	HW_KM_RCP_KEYWAY_A,
	HW_KM_RCP_KEYWAY_B,
	HW_KM_RCP_SYNERGY_MODE,
	HW_KM_RCP_DW0_B_DYN,
	HW_KM_RCP_DW0_B_OFS,
	HW_KM_RCP_DW2_B_DYN,
	HW_KM_RCP_DW2_B_OFS,
	HW_KM_RCP_SW4_B_DYN,
	HW_KM_RCP_SW4_B_OFS,
	HW_KM_RCP_SW5_B_DYN,
	HW_KM_RCP_SW5_B_OFS,
	HW_KM_CAM_W0,
	HW_KM_CAM_W1,
	HW_KM_CAM_W2,
	HW_KM_CAM_W3,
	HW_KM_CAM_W4,
	HW_KM_CAM_W5,
	HW_KM_CAM_FT0,
	HW_KM_CAM_FT1,
	HW_KM_CAM_FT2,
	HW_KM_CAM_FT3,
	HW_KM_CAM_FT4,
	HW_KM_CAM_FT5,
	HW_KM_TCAM_T,
	HW_KM_TCI_COLOR,
	HW_KM_TCI_FT,
	HW_KM_TCQ_BANK_MASK,
	HW_KM_TCQ_QUAL
};
bool hw_mod_km_present(struct flow_api_backend_s *be);
int hw_mod_km_alloc(struct flow_api_backend_s *be);
void hw_mod_km_free(struct flow_api_backend_s *be);
int hw_mod_km_reset(struct flow_api_backend_s *be);
int hw_mod_km_rcp_flush(struct flow_api_backend_s *be, int start_idx, int count);
int hw_mod_km_cam_flush(struct flow_api_backend_s *be, int start_bank, int start_record,
	int count);
int hw_mod_km_tcam_flush(struct flow_api_backend_s *be, int start_bank, int count);
int hw_mod_km_tcam_set(struct flow_api_backend_s *be, enum hw_km_e field, int bank, int byte,
	int byte_val, uint32_t *value_set);
int hw_mod_km_tci_flush(struct flow_api_backend_s *be, int start_bank, int start_record,
	int count);
int hw_mod_km_tcq_flush(struct flow_api_backend_s *be, int start_bank, int start_record,
	int count);

struct flm_func_s {
	COMMON_FUNC_INFO_S;
	uint32_t nb_categories;
	uint32_t nb_size_mb;
	uint32_t nb_entry_size;
	uint32_t nb_variant;
	uint32_t nb_prios;
	uint32_t nb_pst_profiles;
	uint32_t nb_scrub_profiles;
	uint32_t nb_rpp_clock_in_ps;
	uint32_t nb_load_aps_max;
	union {
		struct hw_mod_flm_v25_s v25;
	};
};

struct hsh_func_s {
	COMMON_FUNC_INFO_S;
	uint32_t nb_rcp;/* number of HSH recipes supported by FPGA */
	/* indication if Toeplitz is supported by FPGA, i.e. 0 - unsupported, 1 - supported */
	uint32_t toeplitz;
	union {
		struct hw_mod_hsh_v5_s v5;
	};
};

struct qsl_func_s {
	COMMON_FUNC_INFO_S;
	uint32_t nb_rcp_categories;
	uint32_t nb_qst_entries;
	union {
		struct hw_mod_qsl_v7_s v7;
	};
};

struct slc_lr_func_s {
	COMMON_FUNC_INFO_S;
	union {
		struct hw_mod_slc_lr_v2_s v2;
	};
};

struct pdb_func_s {
	COMMON_FUNC_INFO_S;
	uint32_t nb_pdb_rcp_categories;

	union {
		struct hw_mod_pdb_v9_s v9;
	};
};

struct tpe_func_s {
	COMMON_FUNC_INFO_S;
	uint32_t nb_rcp_categories;
	uint32_t nb_ifr_categories;
	uint32_t nb_cpy_writers;
	uint32_t nb_rpl_depth;
	uint32_t nb_rpl_ext_categories;
	union {
		struct hw_mod_tpe_v3_s v3;
	};
};

enum debug_mode_e {
	FLOW_BACKEND_DEBUG_MODE_NONE = 0x0000,
	FLOW_BACKEND_DEBUG_MODE_WRITE = 0x0001
};

struct flow_api_backend_ops {
	int version;
	int (*set_debug_mode)(void *dev, enum debug_mode_e mode);
	int (*get_nb_phy_port)(void *dev);
	int (*get_nb_rx_port)(void *dev);
	int (*get_ltx_avail)(void *dev);
	int (*get_nb_cat_funcs)(void *dev);
	int (*get_nb_categories)(void *dev);
	int (*get_nb_cat_km_if_cnt)(void *dev);
	int (*get_nb_cat_km_if_m0)(void *dev);
	int (*get_nb_cat_km_if_m1)(void *dev);

	int (*get_nb_queues)(void *dev);
	int (*get_nb_km_flow_types)(void *dev);
	int (*get_nb_pm_ext)(void *dev);
	int (*get_nb_len)(void *dev);
	int (*get_kcc_size)(void *dev);
	int (*get_kcc_banks)(void *dev);
	int (*get_nb_km_categories)(void *dev);
	int (*get_nb_km_cam_banks)(void *dev);
	int (*get_nb_km_cam_record_words)(void *dev);
	int (*get_nb_km_cam_records)(void *dev);
	int (*get_nb_km_tcam_banks)(void *dev);
	int (*get_nb_km_tcam_bank_width)(void *dev);
	int (*get_nb_flm_categories)(void *dev);
	int (*get_nb_flm_size_mb)(void *dev);
	int (*get_nb_flm_entry_size)(void *dev);
	int (*get_nb_flm_variant)(void *dev);
	int (*get_nb_flm_prios)(void *dev);
	int (*get_nb_flm_pst_profiles)(void *dev);
	int (*get_nb_flm_scrub_profiles)(void *dev);
	int (*get_nb_flm_load_aps_max)(void *dev);
	int (*get_nb_qsl_categories)(void *dev);
	int (*get_nb_qsl_qst_entries)(void *dev);
	int (*get_nb_pdb_categories)(void *dev);
	int (*get_nb_roa_categories)(void *dev);
	int (*get_nb_tpe_categories)(void *dev);
	int (*get_nb_tx_cpy_writers)(void *dev);
	int (*get_nb_tx_cpy_mask_mem)(void *dev);
	int (*get_nb_tx_rpl_depth)(void *dev);
	int (*get_nb_tx_rpl_ext_categories)(void *dev);
	int (*get_nb_tpe_ifr_categories)(void *dev);
	int (*get_nb_rpp_per_ps)(void *dev);
	int (*get_nb_hsh_categories)(void *dev);
	int (*get_nb_hsh_toeplitz)(void *dev);

	int (*alloc_rx_queue)(void *dev, int queue_id);
	int (*free_rx_queue)(void *dev, int hw_queue);

	/* CAT */
	bool (*get_cat_present)(void *dev);
	uint32_t (*get_cat_version)(void *dev);
	int (*cat_cfn_flush)(void *dev, const struct cat_func_s *cat, int cat_func, int cnt);
	int (*cat_kce_flush)(void *dev, const struct cat_func_s *cat, int km_if_idx, int index,
		int cnt);
	int (*cat_kcs_flush)(void *dev, const struct cat_func_s *cat, int km_if_idx, int cat_func,
		int cnt);
	int (*cat_fte_flush)(void *dev, const struct cat_func_s *cat, int km_if_idx, int index,
		int cnt);
	int (*cat_cte_flush)(void *dev, const struct cat_func_s *cat, int cat_func, int cnt);
	int (*cat_cts_flush)(void *dev, const struct cat_func_s *cat, int index, int cnt);
	int (*cat_cot_flush)(void *dev, const struct cat_func_s *cat, int cat_func, int cnt);
	int (*cat_cct_flush)(void *dev, const struct cat_func_s *cat, int index, int cnt);
	int (*cat_exo_flush)(void *dev, const struct cat_func_s *cat, int index, int cnt);
	int (*cat_rck_flush)(void *dev, const struct cat_func_s *cat, int index, int cnt);
	int (*cat_len_flush)(void *dev, const struct cat_func_s *cat, int index, int cnt);
	int (*cat_kcc_flush)(void *dev, const struct cat_func_s *cat, int index, int cnt);

	/* KM */
	bool (*get_km_present)(void *dev);
	uint32_t (*get_km_version)(void *dev);
	int (*km_rcp_flush)(void *dev, const struct km_func_s *km, int category, int cnt);
	int (*km_cam_flush)(void *dev, const struct km_func_s *km, int bank, int record, int cnt);
	int (*km_tcam_flush)(void *dev, const struct km_func_s *km, int bank, int byte, int value,
		int cnt);
	int (*km_tci_flush)(void *dev, const struct km_func_s *km, int bank, int record, int cnt);
	int (*km_tcq_flush)(void *dev, const struct km_func_s *km, int bank, int record, int cnt);

	/* FLM */
	bool (*get_flm_present)(void *dev);
	uint32_t (*get_flm_version)(void *dev);
	int (*flm_control_flush)(void *dev, const struct flm_func_s *flm);
	int (*flm_status_flush)(void *dev, const struct flm_func_s *flm);
	int (*flm_status_update)(void *dev, const struct flm_func_s *flm);
	int (*flm_scan_flush)(void *dev, const struct flm_func_s *flm);
	int (*flm_load_bin_flush)(void *dev, const struct flm_func_s *flm);
	int (*flm_prio_flush)(void *dev, const struct flm_func_s *flm);
	int (*flm_pst_flush)(void *dev, const struct flm_func_s *flm, int index, int cnt);
	int (*flm_rcp_flush)(void *dev, const struct flm_func_s *flm, int index, int cnt);
	int (*flm_scrub_flush)(void *dev, const struct flm_func_s *flm, int index, int cnt);
	int (*flm_buf_ctrl_update)(void *dev, const struct flm_func_s *flm);
	int (*flm_stat_update)(void *dev, const struct flm_func_s *flm);
	int (*flm_lrn_data_flush)(void *be_dev, const struct flm_func_s *flm,
		const uint32_t *lrn_data, uint32_t records,
		uint32_t *handled_records, uint32_t words_per_record,
		uint32_t *inf_word_cnt, uint32_t *sta_word_cnt);
	int (*flm_inf_sta_data_update)(void *be_dev, const struct flm_func_s *flm,
		uint32_t *inf_data, uint32_t inf_size,
		uint32_t *inf_word_cnt, uint32_t *sta_data,
		uint32_t sta_size, uint32_t *sta_word_cnt);

	/* HSH */
	bool (*get_hsh_present)(void *dev);
	uint32_t (*get_hsh_version)(void *dev);
	int (*hsh_rcp_flush)(void *dev, const struct hsh_func_s *hsh, int category, int cnt);

	/* QSL */
	bool (*get_qsl_present)(void *dev);
	uint32_t (*get_qsl_version)(void *dev);
	int (*qsl_rcp_flush)(void *dev, const struct qsl_func_s *qsl, int category, int cnt);
	int (*qsl_qst_flush)(void *dev, const struct qsl_func_s *qsl, int entry, int cnt);
	int (*qsl_qen_flush)(void *dev, const struct qsl_func_s *qsl, int entry, int cnt);
	int (*qsl_unmq_flush)(void *dev, const struct qsl_func_s *qsl, int entry, int cnt);

	/* SLC LR */
	bool (*get_slc_lr_present)(void *dev);
	uint32_t (*get_slc_lr_version)(void *dev);
	int (*slc_lr_rcp_flush)(void *dev, const struct slc_lr_func_s *slc_lr, int category,
		int cnt);

	/* PDB */
	bool (*get_pdb_present)(void *dev);
	uint32_t (*get_pdb_version)(void *dev);
	int (*pdb_rcp_flush)(void *dev, const struct pdb_func_s *pdb, int category, int cnt);
	int (*pdb_config_flush)(void *dev, const struct pdb_func_s *pdb);

	/* TPE */
	bool (*get_tpe_present)(void *dev);
	uint32_t (*get_tpe_version)(void *dev);
	int (*tpe_rpp_rcp_flush)(void *dev, const struct tpe_func_s *tpe, int index, int cnt);
	int (*tpe_rpp_ifr_rcp_flush)(void *dev, const struct tpe_func_s *tpe, int index, int cnt);
	int (*tpe_ifr_rcp_flush)(void *dev, const struct tpe_func_s *tpe, int index, int cnt);
	int (*tpe_ins_rcp_flush)(void *dev, const struct tpe_func_s *tpe, int index, int cnt);
	int (*tpe_rpl_rcp_flush)(void *dev, const struct tpe_func_s *tpe, int index, int cnt);
	int (*tpe_rpl_ext_flush)(void *dev, const struct tpe_func_s *tpe, int index, int cnt);
	int (*tpe_rpl_rpl_flush)(void *dev, const struct tpe_func_s *tpe, int index, int cnt);
	int (*tpe_cpy_rcp_flush)(void *dev, const struct tpe_func_s *tpe, int index, int cnt);
	int (*tpe_hfu_rcp_flush)(void *dev, const struct tpe_func_s *tpe, int index, int cnt);
	int (*tpe_csu_rcp_flush)(void *dev, const struct tpe_func_s *tpe, int index, int cnt);
};

struct flow_api_backend_s {
	void *be_dev;
	const struct flow_api_backend_ops *iface;

	/* flow filter FPGA modules */
	struct cat_func_s cat;
	struct km_func_s km;

	/* NIC attributes */
	unsigned int num_phy_ports;
	unsigned int num_rx_ports;

	/* flow filter resource capacities */
	unsigned int max_categories;
	unsigned int max_queues;
};

int flow_api_backend_init(struct flow_api_backend_s *dev, const struct flow_api_backend_ops *iface,
	void *be_dev);
int flow_api_backend_done(struct flow_api_backend_s *dev);

#endif  /* _HW_MOD_BACKEND_H_ */