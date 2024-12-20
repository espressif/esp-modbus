/*
 * SPDX-FileCopyrightText: 2021-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include "mb_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mb_base_t mb_base_t;  /*!< Type of moddus object */

mb_err_enum_t mbm_rq_read_inp_reg(mb_base_t *inst, uint8_t snd_addr, uint16_t reg_addr, uint16_t reg_num, uint32_t tout);
mb_err_enum_t mbm_rq_write_holding_reg(mb_base_t *inst, uint8_t snd_addr, uint16_t reg_addr, uint16_t reg_data, uint32_t tout);
mb_err_enum_t mbm_rq_write_multi_holding_reg(mb_base_t *inst, uint8_t snd_addr, uint16_t reg_addr, uint16_t reg_wr_addr, uint16_t *data_ptr, uint32_t tout);
mb_err_enum_t mbm_rq_read_holding_reg(mb_base_t *inst, uint8_t snd_addr, uint16_t reg_addr, uint16_t reg_num, uint32_t tout);
mb_err_enum_t mbm_rq_rw_multi_holding_reg(mb_base_t *inst, uint8_t snd_addr, uint16_t rd_reg_addr, 
                                            uint16_t rd_reg_num, uint16_t *data_ptr, uint16_t wr_reg_addr, uint16_t wr_reg_num, uint32_t tout);
mb_err_enum_t mbm_rq_read_discrete_inputs(mb_base_t *inst, uint8_t snd_addr, uint16_t discrete_addr, uint16_t discrete_num, uint32_t tout);
mb_err_enum_t mbm_rq_read_coils(mb_base_t *inst, uint8_t snd_addr, uint16_t coil_addr, uint16_t coil_num, uint32_t tout);
mb_err_enum_t mbm_rq_write_coil(mb_base_t *inst, uint8_t snd_addr, uint16_t coil_addr, uint16_t coil_data, uint32_t tout);
mb_err_enum_t mbm_rq_write_multi_coils(mb_base_t *inst, uint8_t snd_addr, uint16_t coil_addr, uint16_t coil_num, uint8_t *data_ptr, uint32_t tout);

#ifdef __cplusplus
}
#endif