/*
 * SPDX-FileCopyrightText: 2021-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <stdint.h>
#include "mb_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MB_FUNC_CODE_MIN            (0x01)
#define MB_FUNC_CODE_MAX            (0x7F)

typedef struct mb_base_t mb_base_t;

#if MB_FUNC_OTHER_REP_SLAVEID_ENABLED
mb_exception_t mbs_fn_report_slave_id(mb_base_t *inst, uint8_t *frame_ptr,uint16_t *len_buf);
mb_exception_t mbm_fn_report_slave_id(mb_base_t *inst, uint8_t *frame_ptr,uint16_t *len_buf);
#endif

#if MB_FUNC_READ_INPUT_ENABLED
mb_exception_t mbs_fn_read_input_reg(mb_base_t *inst, uint8_t *frame_ptr,uint16_t *len_buf);
mb_exception_t mbm_fn_read_inp_reg(mb_base_t *inst, uint8_t *frame_ptr,uint16_t *len_buf);
#endif

#if MB_FUNC_READ_HOLDING_ENABLED
mb_exception_t mbs_fn_read_holding_reg(mb_base_t *inst, uint8_t *frame_ptr,uint16_t *len_buf);
mb_exception_t mbm_fn_read_holding_reg(mb_base_t *inst, uint8_t *frame_ptr,uint16_t *len_buf);
#endif

#if MB_FUNC_WRITE_HOLDING_ENABLED
mb_exception_t mbs_fn_write_holding_reg(mb_base_t *inst, uint8_t *frame_ptr, uint16_t *len_buf);
mb_exception_t mbm_fn_write_holding_reg(mb_base_t *inst, uint8_t *frame_ptr, uint16_t *len_buf);
#endif

#if MB_FUNC_WRITE_MULTIPLE_HOLDING_ENABLED
mb_exception_t mbs_fn_write_multi_holding_reg(mb_base_t *inst, uint8_t *frame_ptr, uint16_t *len_buf);
mb_exception_t mbm_fn_write_multi_holding_reg(mb_base_t *inst, uint8_t *frame_ptr, uint16_t *len_buf);
#endif

#if MB_FUNC_READ_COILS_ENABLED
mb_exception_t mbs_fn_read_coils(mb_base_t *inst, uint8_t *frame_ptr,uint16_t *len_buf);
mb_exception_t mbm_fn_read_coils(mb_base_t *inst, uint8_t *frame_ptr,uint16_t *len_buf);
#endif

#if MB_FUNC_WRITE_COIL_ENABLED
mb_exception_t mbs_fn_write_coil(mb_base_t *inst, uint8_t *frame_ptr, uint16_t *len_buf);
mb_exception_t mbm_fn_write_coil(mb_base_t *inst, uint8_t *frame_ptr, uint16_t *len_buf);
#endif

#if MB_FUNC_WRITE_MULTIPLE_COILS_ENABLED
mb_exception_t mbs_fn_write_multi_coils(mb_base_t *inst, uint8_t *frame_ptr, uint16_t *len_buf);
mb_exception_t mbm_fn_write_multi_coils(mb_base_t *inst, uint8_t *frame_ptr, uint16_t *len_buf);
#endif

#if MB_FUNC_READ_DISCRETE_INPUTS_ENABLED
mb_exception_t mbs_fn_read_discrete_inp(mb_base_t *inst, uint8_t *frame_ptr, uint16_t *len_buf);
mb_exception_t mbm_fn_read_discrete_inputs(mb_base_t *inst, uint8_t *frame_ptr, uint16_t *len_buf);
#endif

#if MB_FUNC_READWRITE_HOLDING_ENABLED
mb_exception_t mbs_fn_rw_multi_holding_reg(mb_base_t *inst, uint8_t *frame_ptr,uint16_t *len_buf);
mb_exception_t mbm_fn_rw_multi_holding_regs(mb_base_t *inst, uint8_t *frame_ptr, uint16_t *len_buf);
#endif

#ifdef __cplusplus
}
#endif
