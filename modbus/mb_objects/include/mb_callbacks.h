/*
 * SPDX-FileCopyrightText: 2021-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "mb_common.h"
#include "mb_proto.h"
#include "mb_func.h"

typedef mb_err_enum_t (*reg_input_cb_fp)(mb_base_t *inst, uint8_t *reg_buff, uint16_t reg_addr, uint16_t reg_num);
typedef mb_err_enum_t (*reg_holding_cb_fp)(mb_base_t *inst, uint8_t *reg_buff, uint16_t reg_addr, uint16_t reg_num, mb_reg_mode_enum_t mode);
typedef mb_err_enum_t (*reg_coils_cb_fp)(mb_base_t *inst, uint8_t *reg_buff, uint16_t reg_addr, uint16_t coil_num, mb_reg_mode_enum_t mode);
typedef mb_err_enum_t (*reg_discrete_cb_fp)(mb_base_t *inst, uint8_t *reg_buff, uint16_t reg_addr, uint16_t disc_num);

typedef struct _mb_rw_callbacks {
    reg_input_cb_fp reg_input_cb;
    reg_holding_cb_fp reg_holding_cb;
    reg_coils_cb_fp reg_coils_cb;
    reg_discrete_cb_fp reg_discrete_cb;
} mb_rw_callbacks_t;

#ifdef __cplusplus
}
#endif

